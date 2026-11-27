"""Failing spec for MCP tools that export a session or read local files.

The Fortress MCP server registers cookie export, in-page script execution,
local document extraction, and the raw CDP endpoint as read-only. A client
that honors that hint runs the call with no approval and returns the result.

These tests drive the server's tools/list and tools/call paths. They fail
while the tools are still advertised as reads, and while extract_document
returns a file from outside the write sandbox. They pass once those tools
require approval and local document reads stay inside the sandbox.

Run (expected to fail until that fix):

    python tools/tests/test_mcp_sensitive_tool_hints.py

Needs the mcp Python SDK (1.28.x), the tilion package that provides
tilion.facade and tilion.core, and google-chrome on PATH. The browser is a
local headless process started by this file.
"""
from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

# The repo root contains a package named mcp/ that would shadow the MCP SDK.
_REPO = Path(__file__).resolve().parents[2]
sys.path = [p for p in sys.path if p not in ("", str(_REPO)) and Path(p or ".").resolve() != _REPO]

from tilion.core.engine.cdp import CDPSession  # noqa: E402
from tilion.core.tab import Tab  # noqa: E402
from tilion.facade import Tilion  # noqa: E402


def _load_server():
    spec = importlib.util.spec_from_file_location(
        "fortress_mcp_server_under_test", _REPO / "mcp" / "server.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


SERVER = _load_server()

# Tools whose result or side effect is a session or a local file, but which
# the server currently labels read-only. click_button is a real write and is
# only here so the approval rule is not inverted.
SENSITIVE_TOOLS = (
    "get_cookies",
    "evaluate_js",
    "extract_document",
    "get_stealth_cdp_endpoint",
)
COOKIE_VALUE = "canary-cookie-value"
OUTSIDE_HTML = "CANARY-DOC-OUTSIDE"
OUTSIDE_CSV = "CANARY-CSV-OUTSIDE"
INSIDE_HTML = "CANARY-DOC-INSIDE"
SYMLINK_SECRET = "CANARY-DOC-SYMLINK-SECRET"


def codex_auto_requires_approval(annotations) -> bool:
    """Whether OpenAI Codex, in auto approval mode, prompts before the call.

    Copied from codex-rs/core/src/mcp_tool_call.rs at commit
    057d9140a8b356a4b1eb71f01c8e981f2aeef20f. requires_mcp_tool_approval
    (lines 2746-2758) returns false as soon as read_only_hint is true, and
    requires_mcp_tool_approval_for_mode (lines 2761-2772) uses that for
    AppToolApproval::Auto. prepare_mcp_tool_approval (lines 1677-1679) then
    returns NotRequired, and handle_mcp_tool_call (lines 283-399) executes
    the tool and returns its result with no approval.
    """
    read_only = False if annotations is None else bool(annotations.readOnlyHint)
    if read_only:
        return False
    if annotations is None or annotations.destructiveHint is None:
        destructive = True
    else:
        destructive = bool(annotations.destructiveHint)
    if annotations is None or annotations.openWorldHint is None:
        open_world = True
    else:
        open_world = bool(annotations.openWorldHint)
    return destructive or open_world


def _tool_text(result) -> str:
    parts = []
    for block in result:
        text = getattr(block, "text", None)
        if text:
            parts.append(text)
    return "\n".join(parts)


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class _QuietHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


class SensitiveToolHintTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        chrome = shutil.which("google-chrome") or shutil.which("chrome")
        if not chrome:
            raise unittest.SkipTest("google-chrome is not installed")
        cls.http = ThreadingHTTPServer(("127.0.0.1", 0), _QuietHandler)
        cls.http_port = cls.http.server_address[1]
        cls.http_thread = threading.Thread(target=cls.http.serve_forever, daemon=True)
        cls.http_thread.start()
        cls.origin = f"http://127.0.0.1:{cls.http_port}/"

        cls.chrome_port = _free_port()
        cls.chrome_dir = tempfile.mkdtemp(prefix="fortress-mcp-chrome-")
        cls.chrome = subprocess.Popen(
            [
                chrome,
                "--headless=new",
                "--disable-gpu",
                "--no-first-run",
                "--no-default-browser-check",
                f"--remote-debugging-port={cls.chrome_port}",
                f"--user-data-dir={cls.chrome_dir}",
                "about:blank",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        version = cls._wait_json(f"http://127.0.0.1:{cls.chrome_port}/json/version")
        cls.browser_ws = version["webSocketDebuggerUrl"]
        pages = cls._wait_json(f"http://127.0.0.1:{cls.chrome_port}/json/list")
        page = next(item for item in pages if item.get("type") == "page")
        cls.page_ws = page["webSocketDebuggerUrl"]
        cls.session = CDPSession(cls.page_ws)
        asyncio.run(cls._prepare_page(page["id"]))

        browser = type("Browser", (), {"is_started": True})()
        tilion = Tilion.__new__(Tilion)
        tilion._started = True
        tilion._base_url = None
        tilion._browser = browser
        tilion._current = cls.tab
        tilion._interactive_lock = None
        tilion._fortress = type("Engine", (), {"cdp_url": cls.browser_ws})()
        SERVER._tilion = tilion

        cls.jail = Path(tempfile.mkdtemp(prefix="fortress-mcp-jail-"))
        os.environ["TILION_MCP_WRITE_DIR"] = str(cls.jail)

    @classmethod
    def _wait_json(cls, url: str):
        last = None
        for _ in range(50):
            try:
                with urllib.request.urlopen(url, timeout=0.2) as response:
                    return json.load(response)
            except Exception as exc:  # noqa: BLE001 - chrome is still booting
                last = exc
                if cls.chrome.poll() is not None:
                    break
                import time
                time.sleep(0.1)
        raise RuntimeError(f"chrome debugging endpoint did not come up: {last}")

    @classmethod
    async def _prepare_page(cls, target_id: str):
        await cls.session.connect()
        cls.tab = Tab(target_id, cls.page_ws, browser=None)
        cls.tab._session = cls.session
        cls.tab._closed = False
        await cls.session.send("Page.navigate", {"url": cls.origin})
        await cls.session.send(
            "Network.setCookie",
            {"name": "sid", "value": COOKIE_VALUE, "url": cls.origin},
        )

    @classmethod
    def tearDownClass(cls):
        cls.http.shutdown()
        if cls.chrome.poll() is None:
            os.killpg(cls.chrome.pid, signal.SIGKILL)
        shutil.rmtree(cls.chrome_dir, ignore_errors=True)
        shutil.rmtree(cls.jail, ignore_errors=True)
        SERVER._tilion = None

    def _annotations(self, name: str):
        tools = asyncio.run(SERVER.mcp.list_tools())
        tool = next(item for item in tools if item.name == name)
        return tool.annotations

    def test_sensitive_tools_require_approval_and_writes_still_do(self):
        unlabeled = []
        for name in SENSITIVE_TOOLS:
            if not codex_auto_requires_approval(self._annotations(name)):
                unlabeled.append(name)
        self.assertEqual(
            unlabeled,
            [],
            "these tools are advertised as read-only, so an auto-mode client "
            "runs them and returns the result without approval",
        )
        self.assertTrue(
            codex_auto_requires_approval(self._annotations("click_button")),
            "click_button is a write and must still require approval",
        )

    def test_get_cookies_returns_the_page_jar(self):
        body = _tool_text(asyncio.run(SERVER.mcp.call_tool("get_cookies", {})))
        self.assertIn(COOKIE_VALUE, body)
        self.assertTrue(
            codex_auto_requires_approval(self._annotations("get_cookies")),
            "get_cookies returned the page cookie jar without an approval hint",
        )

    def test_evaluate_js_runs_the_supplied_script_in_the_page(self):
        read_back = _tool_text(asyncio.run(
            SERVER.mcp.call_tool("evaluate_js", {"expression": "document.cookie"})
        ))
        self.assertIn(COOKIE_VALUE, read_back)
        mutated = _tool_text(asyncio.run(
            SERVER.mcp.call_tool(
                "evaluate_js",
                {"expression": 'document.title = "canary-title"'},
            )
        ))
        self.assertIn("canary-title", mutated)
        self.assertTrue(
            codex_auto_requires_approval(self._annotations("evaluate_js")),
            "evaluate_js ran the supplied script in the page without an approval hint",
        )

    def test_cdp_endpoint_returns_the_live_debugger_url(self):
        body = _tool_text(asyncio.run(
            SERVER.mcp.call_tool("get_stealth_cdp_endpoint", {})
        ))
        self.assertIn(self.browser_ws, body)
        self.assertTrue(
            codex_auto_requires_approval(self._annotations("get_stealth_cdp_endpoint")),
            "get_stealth_cdp_endpoint returned the browser debugger URL "
            "without an approval hint",
        )

    def test_extract_document_refuses_files_outside_the_jail(self):
        outside = Path(tempfile.mkdtemp(prefix="fortress-mcp-outside-"))
        html = outside / "secret.html"
        csv = outside / "secret.csv"
        html.write_text(f"<html><body><p>{OUTSIDE_HTML}</p></body></html>", encoding="utf-8")
        csv.write_text(f"name,note\nalice,{OUTSIDE_CSV}\n", encoding="utf-8")
        (self.jail / "nested").mkdir()
        # Lexical path is under the jail; the resolved path is the outside file.
        escaped = self.jail / "nested" / ".." / ".." / outside.name / html.name
        before = {path.name for path in self.jail.rglob("*")}
        try:
            for source in (html, csv, escaped):
                with self.subTest(source=str(source)):
                    body = _tool_text(asyncio.run(
                        SERVER.mcp.call_tool("extract_document", {"source": str(source)})
                    ))
                    for marker in (OUTSIDE_HTML, OUTSIDE_CSV):
                        self.assertNotIn(
                            marker,
                            body,
                            f"extract_document returned {source} from outside the jail",
                        )
            after = {path.name for path in self.jail.rglob("*")}
            self.assertEqual(before, after, "a refused document read created a file")
            self.assertEqual(html.read_text(encoding="utf-8").count(OUTSIDE_HTML), 1)
        finally:
            shutil.rmtree(outside, ignore_errors=True)

    def test_extract_document_still_reads_a_file_inside_the_jail(self):
        inside = self.jail / "notes.html"
        inside.write_text(f"<html><body><p>{INSIDE_HTML}</p></body></html>", encoding="utf-8")
        body = _tool_text(asyncio.run(
            SERVER.mcp.call_tool("extract_document", {"source": str(inside)})
        ))
        self.assertIn(INSIDE_HTML, body)

    def test_extract_document_does_not_follow_a_symlink_swapped_after_the_check(self):
        """The path that was checked has to be the path that is opened.

        The link starts at a file inside the jail. The open that actually
        reads it retargets the link at an outside file. A check that resolves
        the link, then opens the original path again, returns the outside file.
        """
        inside = self.jail / "inside.html"
        inside.write_text("<html><body><p>CANARY-DOC-LINK-INSIDE</p></body></html>", encoding="utf-8")
        outside_dir = Path(tempfile.mkdtemp(prefix="fortress-mcp-link-"))
        secret = outside_dir / "secret.html"
        secret.write_text(f"<html><body><p>{SYMLINK_SECRET}</p></body></html>", encoding="utf-8")
        link = self.jail / "link.html"
        link.symlink_to(inside)
        link_name = os.path.normpath(os.fspath(link))
        real_read_text = Path.read_text

        def read_text_and_swap(self, *args, **kwargs):
            # tilion/core/scraping/extractor.py _extract_html_file reads a path
            # with Path.read_text. Retarget just before that read so a check
            # that resolved the old target, then opens this path again, sees
            # the outside file.
            try:
                same = os.path.normpath(os.fspath(self)) == link_name
            except TypeError:
                same = False
            if same and link.is_symlink():
                link.unlink()
                link.symlink_to(secret)
            return real_read_text(self, *args, **kwargs)

        Path.read_text = read_text_and_swap
        try:
            body = _tool_text(asyncio.run(
                SERVER.mcp.call_tool("extract_document", {"source": str(link)})
            ))
        finally:
            Path.read_text = real_read_text
            shutil.rmtree(outside_dir, ignore_errors=True)
        self.assertNotIn(SYMLINK_SECRET, body)


if __name__ == "__main__":
    unittest.main()
