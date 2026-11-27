"""SSRF: alternate IPv4 literals bypass the MCP navigation guard.

The guard in mcp/server.py decides with Python's ipaddress module and with
getaddrinfo. Chromium (the browser these tools drive) parses a different IPv4
grammar: it strips one trailing dot, then accepts hex, octal, and short forms.
On this platform getaddrinfo("0177.0.0.1.") returns the public address
177.0.0.1, so both the MCP check and tilion's pre-navigation host_blocked()
allow the URL, and Chrome opens 127.0.0.1.

These tests call the real tool functions. They fail while that request is
made and pass once every navigating tool rejects the URL before any request.
A check that merely repeats getaddrinfo still fails them, because the browser
is given the original URL string.

Run from the repo root:

    python mcp/tests/test_ssrf_ip_literal_bypass.py -v

Not covered here, because they never navigate to a caller-supplied host:
press_key, current_page, list_tabs, close_tab, save_profile, load_profile,
list_browser_tasks, search_web, get_egress_info, get_stealth_cdp_endpoint.
"""
from __future__ import annotations

import asyncio
import base64
import importlib.util
import ipaddress
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

MARKER = "LOOPBACK_BODY_MARKER"
REPO = Path(__file__).resolve().parents[2]
SERVER_PY = REPO / "mcp" / "server.py"

def _load_server():
    """Import this commit's mcp/server.py without the tilion or mcp packages."""
    def mod(name):
        module = types.ModuleType(name)
        sys.modules[name] = module
        return module

    mcp = mod("mcp")
    server = mod("mcp.server")
    fast = mod("mcp.server.fastmcp")
    mcp_types = mod("mcp.types")
    mcp.server = server
    server.fastmcp = fast
    mcp.types = mcp_types

    class Context:
        pass

    class ToolAnnotations:
        def __init__(self, **_kwargs):
            pass

    class FastMCP:
        def __init__(self, *_args, **_kwargs):
            pass

        def tool(self, *_args, **_kwargs):
            def deco(fn):
                return fn
            return deco

        def run(self):
            pass

    fast.Context = Context
    fast.FastMCP = FastMCP
    mcp_types.ToolAnnotations = ToolAnnotations

    facade = mod("tilion.facade")
    tilion = mod("tilion")
    tilion.facade = facade

    class Tilion:
        @staticmethod
        def list_tasks():
            return ["download_file"]

    facade.Tilion = Tilion
    spec = importlib.util.spec_from_file_location("fortress_mcp_server_under_test", SERVER_PY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _addr_blocked(ip_str: str) -> bool:
    """netguard.addr_blocked: non-literals are blocked; mapped v4 is rechecked."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
            or ip.is_multicast or ip.is_unspecified):
        return True
    mapped = getattr(ip, "ipv4_mapped", None)
    if ip.version == 6 and mapped is not None:
        return _addr_blocked(str(mapped))
    return False


async def _host_blocked(host: str, port: int = 0) -> bool:
    """netguard.host_blocked from tilion 0.1.12, without its process-wide cache.

    A failed lookup is blocked. The lookup uses the original host, so a
    trailing dot is not stripped before getaddrinfo.
    """
    if not host:
        return True
    normalized = host.lower().rstrip(".")
    if normalized in {"metadata", "localhost", "metadata.google.internal"}:
        return True
    if normalized.endswith((".internal", ".local", ".localhost")):
        return True
    try:
        ipaddress.ip_address(normalized)
    except ValueError:
        pass
    else:
        return _addr_blocked(normalized)
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(
            host, port or None, proto=socket.IPPROTO_TCP)
    except Exception:
        return True
    if not infos:
        return True
    return any(_addr_blocked(info[4][0]) for info in infos)


class _Hits:
    def __init__(self):
        self.paths: list[str] = []

    def add(self, path: str) -> None:
        self.paths.append(path)


class _Handler(BaseHTTPRequestHandler):
    hits: _Hits

    def do_GET(self):  # noqa: N802
        type(self).hits.add(self.path)
        body = f"<html><body>{MARKER}</body></html>".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _fmt, *_args):
        return


class _WebSocket:
    def __init__(self, sock: socket.socket):
        self._sock = sock
        self._buf = b""

    def send(self, text: str) -> None:
        data = text.encode()
        mask = os.urandom(4)
        header = bytearray([0x81])
        length = len(data)
        if length < 126:
            header.append(0x80 | length)
        elif length < 65536:
            header.append(0x80 | 126)
            header += struct.pack("!H", length)
        else:
            header.append(0x80 | 127)
            header += struct.pack("!Q", length)
        header += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        self._sock.sendall(bytes(header) + masked)

    def _recv_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self._sock.recv(65536)
            if not chunk:
                raise ConnectionError("websocket closed")
            self._buf += chunk
        out, self._buf = self._buf[:n], self._buf[n:]
        return out

    def recv(self) -> str:
        while True:
            first, second = self._recv_exact(2)
            opcode = first & 0x0F
            length = second & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._recv_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._recv_exact(8))[0]
            payload = self._recv_exact(length)
            if opcode == 9:  # ping
                continue
            if opcode == 8:
                raise ConnectionError("websocket close")
            if opcode == 1:
                return payload.decode()


def _ws_connect(url: str) -> _WebSocket:
    parsed = urlparse(url)
    sock = socket.create_connection((parsed.hostname, parsed.port))
    key = base64.b64encode(os.urandom(16)).decode()
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {parsed.hostname}:{parsed.port}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "\r\n"
    )
    sock.sendall(req.encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("cdp handshake failed")
        buf += chunk
    return _WebSocket(sock)


class _Chrome:
    """One headless Chrome. Navigation is CDP Page.navigate of the original URL."""

    def __init__(self):
        self._proc = None
        self._profile = tempfile.mkdtemp(prefix="ssrf-chrome-")
        self._ws = None
        self._mid = 0
        self._lock = threading.Lock()

    def start(self) -> None:
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
        probe.close()
        binary = shutil.which("google-chrome") or shutil.which("google-chrome-stable")
        if not binary:
            raise unittest.SkipTest("google-chrome is not installed")
        self._proc = subprocess.Popen(
            [
                binary, "--headless=new", "--disable-gpu", "--no-sandbox",
                "--disable-dev-shm-usage", "--no-first-run",
                f"--remote-debugging-port={port}",
                f"--user-data-dir={self._profile}", "about:blank",
            ],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        version = None
        for _ in range(100):
            try:
                with urllib.request.urlopen(
                        f"http://127.0.0.1:{port}/json/version", timeout=0.2) as resp:
                    version = json.load(resp)
                    break
            except Exception:
                if self._proc.poll() is not None:
                    break
                time.sleep(0.1)
        if not version:
            self.stop()
            raise RuntimeError("Chrome DevTools endpoint did not come up")
        self._ws = _ws_connect(version["webSocketDebuggerUrl"])

    def stop(self) -> None:
        if self._proc is not None and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        shutil.rmtree(self._profile, ignore_errors=True)

    def _call(self, method: str, params: dict | None = None, session: str | None = None):
        self._mid += 1
        message = {"id": self._mid, "method": method}
        if params:
            message["params"] = params
        if session:
            message["sessionId"] = session
        expect = self._mid
        self._ws.send(json.dumps(message))
        while True:
            incoming = json.loads(self._ws.recv())
            if incoming.get("id") == expect:
                if "error" in incoming:
                    raise RuntimeError(incoming["error"])
                return incoming.get("result", {})

    def navigate(self, url: str) -> str:
        """Page.navigate the given URL and return document.body.innerText.

        This is the same CDP command Tab.goto sends (tilion/core/tab.py).
        """
        with self._lock:
            created = self._call("Target.createTarget", {"url": "about:blank"})
            target = created["targetId"]
            try:
                attached = self._call(
                    "Target.attachToTarget",
                    {"targetId": target, "flatten": True})
                session = attached["sessionId"]
                self._call("Page.enable", session=session)
                self._call("Page.navigate", {"url": url}, session=session)
                text = ""
                for _ in range(25):
                    evaluated = self._call(
                        "Runtime.evaluate",
                        {
                            "expression": "document.body ? document.body.innerText : ''",
                            "returnByValue": True,
                        },
                        session=session,
                    )
                    text = ((evaluated.get("result") or {}).get("value")) or ""
                    if MARKER in text:
                        break
                return text
            finally:
                try:
                    self._call("Target.closeTarget", {"targetId": target})
                except Exception:
                    pass


class _Browser:
    """Stand-in for Tilion that follows the real guard-then-navigate split.

    fetch/extract/crawl/read/download and the other page methods run
    host_blocked first, matching facade._guard_url. extract_url does not:
    Extractor.extract_url calls browser.visit, which sends the URL straight
    to Page.goto.
    """

    def __init__(self, chrome: _Chrome, hits: _Hits):
        self._chrome = chrome
        self._hits = hits
        self.last = ""

    async def _open(self, url: str | None, *, guarded: bool) -> str:
        if not url:
            return ""
        parsed = urlparse(url)
        if guarded and await _host_blocked(parsed.hostname or "", parsed.port or 0):
            raise PermissionError(f"refused private/loopback target {url!r}")
        # Chrome would open this host itself. Only the loopback address of
        # this test's server is contacted; any other address is recorded as
        # a navigation attempt and not dialed.
        if _chromium_ipv4(parsed.hostname or "") != "127.0.0.1":
            self._hits.paths.append("navigation-attempt")
            self.last = ""
            return ""
        before = len(self._hits.paths)
        text = await asyncio.to_thread(self._chrome.navigate, url)
        if len(self._hits.paths) == before:
            raise AssertionError(
                f"navigation did not reach the local server: {url}")
        self.last = text
        return text

    async def fetch(self, url, **_kwargs):
        text = await self._open(url, guarded=True)
        return {"url": url, "status": "ok", "title": "t", "html": text, "text": text}

    async def extract(self, url, **_kwargs):
        text = await self._open(url, guarded=True)
        return {"url": url, "markdown": text, "text": text, "html": text}

    async def crawl(self, url, **_kwargs):
        await self._open(url, guarded=True)
        return {"pages_crawled": 1, "documents": [{"url": url, "text": self.last}]}

    async def recon(self, url, **_kwargs):
        await self._open(url, guarded=True)
        return {"api_endpoints": [], "body": self.last}

    async def screenshot(self, url, path=None, **_kwargs):
        await self._open(url, guarded=True)
        if path:
            Path(path).write_bytes(self.last.encode())
        return {"path": path, "png_base64": base64.b64encode(self.last.encode()).decode()}

    async def save(self, url, path, **_kwargs):
        await self._open(url, guarded=True)
        Path(path).write_text(self.last)
        return {"path": path}

    async def read(self, url, **_kwargs):
        text = await self._open(url, guarded=True)
        return {"url": url, "title": "t", "markdown": text}

    async def elements(self, url, **_kwargs):
        await self._open(url, guarded=True)
        return {"url": url, "buttons": [self.last]}

    async def click(self, _text, url=None, **_kwargs):
        text = await self._open(url, guarded=True)
        return {"clicked": True, "url": url, "title": text}

    async def fill(self, _field, _value, url=None, **_kwargs):
        text = await self._open(url, guarded=True)
        return {"url": url, "title": text}

    async def extract_url(self, url, **_kwargs):
        text = await self._open(url, guarded=False)
        return {"url": url, "markdown": text, "text": text, "html": text}

    async def get_html(self, url, **_kwargs):
        text = await self._open(url, guarded=True)
        return {"url": url, "html": text}

    async def evaluate(self, _expression, url=None, **_kwargs):
        text = await self._open(url, guarded=True)
        return {"result": text, "url": url}

    async def wait_for(self, _selector, url=None, **_kwargs):
        text = await self._open(url, guarded=True)
        return {"found": True, "url": url, "text": text}

    async def download(self, url, dest, **_kwargs):
        text = await self._open(url, guarded=True)
        Path(dest).write_text(text)
        return {"url": url, "path": dest, "bytes": len(text)}

    async def get_cookies(self, url=None, **_kwargs):
        await self._open(url, guarded=True)
        return []

    async def detect_waf(self, url=None, **_kwargs):
        text = await self._open(url, guarded=True)
        return {"vendor": None, "body": text}

    async def solve_captcha(self, url=None, **_kwargs):
        text = await self._open(url, guarded=True)
        return {"detected": False, "body": text}

    async def agent(self, _task, url=None, **params):
        await self._open(url, guarded=True)
        for value in params.values():
            if isinstance(value, str) and value[:4].lower() == "http":
                # Flow params are checked only by mcp _check_url, then the
                # task navigates to them. The facade guards the main url only.
                await self._open(value, guarded=False)
        return {"success": True, "data": self.last}


def _chromium_ipv4(host: str) -> str | None:
    """IPv4 literal Chrome 151 parses, or None when it would not treat it as IPv4.

    Mirrors DoIPv4AddressToNumber / IPv4ComponentToNumber in
    url/url_canon_ip.h at Chromium 151.0.7908.0: one trailing dot is removed,
    a leading 0 selects octal, and 0x selects hex. Used only to refuse a
    connection that would not land on this test's loopback server.
    """
    host = unquote(host)
    if host.endswith("."):
        host = host[:-1]
    if not host or ":" in host or host.count(".") > 3:
        return None
    parts = host.split(".")
    values_from_end: list[int] = []
    for part in reversed(parts):
        if not part or not part.isascii():
            return None
        base = 10
        digits = part
        if part[0] == "0" and len(part) > 1:
            if part[1] in "xX":
                base = 16
                digits = part[2:]
            else:
                base = 8
                digits = part[1:]
        while digits.startswith("0") and len(digits) > 1:
            digits = digits[1:]
        if digits == "":
            number = 0
        else:
            try:
                number = int(digits, base)
            except ValueError:
                return None
        if number > 0xFFFFFFFF:
            return None
        values_from_end.append(number)
    count = len(values_from_end)
    if count == 0 or count > 4:
        return None
    address = [0, 0, 0, 0]
    for index in range(count - 1, 0, -1):
        if values_from_end[index] > 255:
            return None
        address[count - index - 1] = values_from_end[index]
    last = values_from_end[0]
    for index in range(4, count - 1, -1):
        address[index - 1] = last & 0xFF
        last >>= 8
    if last != 0:
        return None
    return ".".join(str(part) for part in address)


def _contains_marker(value) -> bool:
    if isinstance(value, str):
        return MARKER in value
    if isinstance(value, dict):
        return any(_contains_marker(v) for v in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_marker(v) for v in value)
    return False


class SsrfIpLiteralBypassTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hits = _Hits()
        _Handler.hits = cls.hits
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        cls.port = cls.httpd.server_address[1]
        cls._thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls._thread.start()
        cls.chrome = _Chrome()
        cls.chrome.start()
        cls.mod = _load_server()
        cls.write_dir = tempfile.mkdtemp(prefix="ssrf-writes-")
        os.environ["TILION_MCP_WRITE_DIR"] = cls.write_dir
        os.environ.pop("TILION_ALLOW_PRIVATE_EGRESS", None)
        os.environ.pop("TILLION_ALLOW_PRIVATE_EGRESS", None)
        browser = _Browser(cls.chrome, cls.hits)

        async def fake_t():
            return browser

        cls.mod._t = fake_t

    @classmethod
    def tearDownClass(cls):
        cls.chrome.stop()
        cls.httpd.shutdown()
        shutil.rmtree(cls.write_dir, ignore_errors=True)

    def setUp(self):
        self.hits.paths.clear()

    def _url(self, host: str) -> str:
        return f"http://{host}:{self.port}/"

    def _assert_refused(self, result, label: str):
        self.assertFalse(
            self.hits.paths,
            f"{label} requested the loopback server: {self.hits.paths}",
        )
        self.assertFalse(
            _contains_marker(result),
            f"{label} returned the loopback response: {result!r}",
        )
        for path in Path(self.write_dir).rglob("*"):
            if path.is_file():
                self.fail(f"{label} wrote {path} before refusing the URL")

    def test_dotted_decimal_loopback_never_connects(self):
        """The guard already blocks a dotted literal. The harness must not fetch it."""
        result = asyncio.run(self.mod.fetch_protected_page(self._url("127.0.0.1")))
        self._assert_refused(result, "127.0.0.1")

    def test_bare_hex_and_decimal_literals_never_connect(self):
        """getaddrinfo of these hosts is the loopback address, so the guard blocks them."""
        for host in ("0x7f000001", "2130706433", "127.1", "0x7f.0x0.0x0.0x1"):
            with self.subTest(host=host):
                self.hits.paths.clear()
                result = asyncio.run(self.mod.fetch_protected_page(self._url(host)))
                self._assert_refused(result, host)

    def test_octal_trailing_dot_is_not_fetched_by_any_navigating_tool(self):
        """0177.0.0.1. resolves to public 177.0.0.1 and Chrome opens 127.0.0.1."""
        url = self._url("0177.0.0.1.")
        calls = [
            ("fetch_protected_page", lambda: self.mod.fetch_protected_page(url)),
            ("extract_page", lambda: self.mod.extract_page(url)),
            ("crawl_site", lambda: self.mod.crawl_site(url, depth=1, max_pages=1)),
            ("recon_site_apis", lambda: self.mod.recon_site_apis(url, duration=1)),
            ("screenshot_page", lambda: self.mod.screenshot_page(url, "shot.png")),
            ("save_page", lambda: self.mod.save_page(url, "page.pdf")),
            ("read_page", lambda: self.mod.read_page(url)),
            ("page_elements", lambda: self.mod.page_elements(url)),
            ("click_button", lambda: self.mod.click_button("Go", url)),
            ("fill_field", lambda: self.mod.fill_field("input", "x", url)),
            ("extract_document", lambda: self.mod.extract_document(url)),
            ("get_page_html", lambda: self.mod.get_page_html(url)),
            ("evaluate_js", lambda: self.mod.evaluate_js("1", url)),
            ("wait_for", lambda: self.mod.wait_for("body", url, 1000)),
            ("download_file", lambda: self.mod.download_file(url, "out.bin")),
            ("get_cookies", lambda: self.mod.get_cookies(url)),
            ("detect_waf", lambda: self.mod.detect_waf(url)),
            ("solve_captcha", lambda: self.mod.solve_captcha(url)),
            ("run_browser_task", lambda: self.mod.run_browser_task(
                "download_file", url, {"href": url})),
        ]
        for name, call in calls:
            with self.subTest(tool=name):
                self.hits.paths.clear()
                for stale in Path(self.write_dir).rglob("*"):
                    if stale.is_file():
                        stale.unlink()
                result = asyncio.run(call())
                self._assert_refused(result, name)

    def test_unresolved_literals_chrome_opens_are_not_fetched(self):
        """These hosts fail DNS, so the MCP guard allows them. extract_document
        then hands the original string to the browser, and Chrome opens 127.0.0.1.
        Tools that call host_blocked first are stopped there; this path is not."""
        hosts = (
            "0x7f000001.",
            "2130706433.",
            "127.1.",
            "0x7f.0x0.0x0.0x1.",
            "0x7f000001%2e",
        )
        for host in hosts:
            with self.subTest(host=host):
                self.hits.paths.clear()
                # Percent-encoded dot survives urlparse and is decoded by Chrome.
                self.assertNotEqual(urlparse(self._url(host)).hostname, "127.0.0.1")
                result = asyncio.run(self.mod.extract_document(self._url(host)))
                self._assert_refused(result, f"extract_document {host}")
                decoded = unquote(urlparse(self._url(host)).hostname or "")
                self.assertTrue(decoded.endswith(".") or "%" not in host)

    def test_metadata_spellings_are_refused_before_any_connection(self):
        """Same grammar for the link-local metadata address. No connection is made."""
        hosts = (
            "0xa9fea9fe.",
            "2852039166.",
            "0251.0376.0251.0376.",
            "0xa9.0xfe.0xa9.0xfe.",
        )
        for host in hosts:
            with self.subTest(host=host):
                self.hits.paths.clear()
                result = asyncio.run(self.mod.extract_document(self._url(host)))
                self._assert_refused(result, f"metadata {host}")


if __name__ == "__main__":
    unittest.main()
