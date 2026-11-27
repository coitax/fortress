"""SSRF via redirects in the MCP navigation tools.

The tools check the caller-supplied URL, then hand that same URL to the
browser or to an HTTP client that follows redirects. A public URL that
redirects to a loopback or link-local address must be rejected before that
address is requested, and before any tool writes a file.

These tests fail while that hop is still followed. Re-checking the original
URL (the same host the guard already allowed) does not make them pass: the
internal target is a different host, served only after the redirect.

Run (from the repo root), with the dependencies this server imports:

    python -m pip install 'tilion==0.1.12' 'tilion-fortress==151.0.7908.0' 'mcp>=1,<2' pytest pytest-asyncio
    TILION_TZ=UTC pytest tests/test_mcp_redirect_ssrf.py -q

tilion 0.1.12 is the release whose mcp/server.py matches this tree.
tilion-fortress 151.0.7908.0 is the engine version in CHROMIUM_VERSION and
the package that still imports as tilion_fortress. The first run downloads
that engine. The test adds 11.0.0.1/32 and 169.254.1.50/32 to the loopback
interface so the public hop stays on this machine. 11.0.0.1 is not a
private, loopback, link-local, or reserved address, so the existing guard
allows it. 169.254.1.50 stands in for a link-local target; the metadata
address is never contacted.
"""
from __future__ import annotations

import asyncio
import importlib.util
import os
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

import pytest

pytestmark = pytest.mark.asyncio(loop_scope="module")

ROOT = Path(__file__).resolve().parents[1]
MARKER = "INTERNAL_ONLY_MARKER"
PUBLIC_BODY = "PUBLIC_OK_BODY"
PUBLIC_IP = "11.0.0.1"
LINK_IP = "169.254.1.50"
LOOP_IP = "127.0.0.1"


def _ensure_addr(ip: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((ip, 0))
    except OSError:
        subprocess.check_call(["sudo", "-n", "ip", "addr", "add", f"{ip}/32", "dev", "lo"])
    finally:
        sock.close()


class _Harness:
    def __init__(self) -> None:
        self.hits: list[tuple[str, str]] = []
        self.servers: list[ThreadingHTTPServer] = []
        self.public_port = 0
        self.loop_port = 0
        self.link_port = 0
        self.write_dir = Path(os.environ["TILION_MCP_WRITE_DIR"])

    def start(self) -> None:
        _ensure_addr(PUBLIC_IP)
        _ensure_addr(LINK_IP)
        self.loop_port = self._serve(LOOP_IP)
        self.link_port = self._serve(LINK_IP)
        self.public_port = self._serve(PUBLIC_IP)

    def _serve(self, host: str) -> int:
        harness = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                harness.hits.append((self.server.server_address[0], self.path))
                path = urlparse(self.path).path
                qs = parse_qs(urlparse(self.path).query)
                if path == "/redir":
                    self._redirect(qs.get("to", [""])[0])
                    return
                if path == "/chain":
                    self._redirect(qs.get("next", [""])[0])
                    return
                if path == "/ok":
                    body = (
                        f"<html><head><title>ok</title></head>"
                        f"<body>{PUBLIC_BODY}</body></html>"
                    ).encode()
                elif path == "/hub":
                    bounce = harness.bounce
                    body = (
                        f"<html><head><title>hub</title></head><body>HUB"
                        f"<a href='{bounce}'>next</a></body></html>"
                    ).encode()
                else:
                    body = (
                        f"<html><head><title>secret</title></head>"
                        f"<body>{MARKER}</body></html>"
                    ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _redirect(self, location: str) -> None:
                self.send_response(302)
                self.send_header("Location", location)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, fmt: str, *args) -> None:
                return

        httpd = ThreadingHTTPServer((host, 0), Handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.servers.append(httpd)
        return httpd.server_address[1]

    def close(self) -> None:
        for httpd in self.servers:
            httpd.shutdown()

    @property
    def loop_url(self) -> str:
        return f"http://{LOOP_IP}:{self.loop_port}/secret"

    @property
    def link_url(self) -> str:
        return f"http://{LINK_IP}:{self.link_port}/secret"

    def _redir_to(self, target: str) -> str:
        return (
            f"http://{PUBLIC_IP}:{self.public_port}/redir?to="
            f"{quote(target, safe='')}"
        )

    @property
    def redir(self) -> str:
        return self._redir_to(self.loop_url)

    @property
    def redir_link(self) -> str:
        return self._redir_to(self.link_url)

    @property
    def chain(self) -> str:
        hop = self._redir_to(self.loop_url)
        return (
            f"http://{PUBLIC_IP}:{self.public_port}/chain?next="
            f"{quote(hop, safe='')}"
        )

    @property
    def ok(self) -> str:
        return f"http://{PUBLIC_IP}:{self.public_port}/ok"

    @property
    def hub(self) -> str:
        return f"http://{PUBLIC_IP}:{self.public_port}/hub"

    @property
    def bounce(self) -> str:
        return self._redir_to(self.loop_url)

    def internal_hits_since(self, start: int) -> list[tuple[str, str]]:
        return [hit for hit in self.hits[start:] if hit[0] != PUBLIC_IP]


def _load_server(write_dir: Path):
    os.environ["TILION_TZ"] = "UTC"
    os.environ["TILION_MCP_PREWARM"] = "0"
    os.environ["TILION_MCP_HEADLESS"] = "1"
    os.environ["TILION_MCP_TOOL_TIMEOUT"] = "45"
    os.environ["TILION_MCP_WRITE_DIR"] = str(write_dir)
    os.environ.pop("TILION_ALLOW_PRIVATE_EGRESS", None)
    os.environ.pop("TILLION_ALLOW_PRIVATE_EGRESS", None)
    os.environ.pop("CAPTCHA_API_KEY", None)
    # The repo's mcp/ package is the server, not the MCP SDK. Drop the repo
    # root so `import mcp` resolves to the installed SDK while this file loads
    # the server from its path.
    root = str(ROOT)
    sys.path[:] = [p for p in sys.path if Path(p or ".").resolve() != ROOT and p != root]
    spec = importlib.util.spec_from_file_location(
        "fortress_mcp_server_under_test", ROOT / "mcp" / "server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def harness(tmp_path_factory: pytest.TempPathFactory):
    write_dir = tmp_path_factory.mktemp("mcp-write")
    box = _Harness()
    box.write_dir = write_dir
    box.start()
    module = _load_server(write_dir)
    box.module = module
    yield box
    tilion = getattr(module, "_tilion", None)
    if tilion is not None:
        try:
            asyncio.run(tilion.close())
        except Exception:
            pass
    box.close()


def _assert_internal_not_reached(box: _Harness, result, start: int) -> None:
    reached = box.internal_hits_since(start)
    assert reached == [], f"internal address was requested: {reached}"
    assert MARKER not in repr(result)
    for path in box.write_dir.rglob("*"):
        if path.is_file():
            assert MARKER.encode() not in path.read_bytes()


async def test_direct_loopback_is_refused_without_a_request(harness: _Harness) -> None:
    start = len(harness.hits)
    result = await harness.module.fetch_protected_page(harness.loop_url)
    assert result.get("status") == "error"
    _assert_internal_not_reached(harness, result, start)


async def test_public_page_is_returned(harness: _Harness) -> None:
    result = await harness.module.fetch_protected_page(harness.ok)
    assert result.get("status") == "ok"
    assert PUBLIC_BODY in result.get("text", "")
    assert MARKER not in repr(result)


def _navigation_cases():
    """Every tool that checks the caller URL and then navigates."""
    return [
        ("fetch_protected_page", lambda m, b: m.fetch_protected_page(b.redir)),
        ("fetch_protected_page_chain", lambda m, b: m.fetch_protected_page(b.chain)),
        ("fetch_protected_page_link_local", lambda m, b: m.fetch_protected_page(b.redir_link)),
        ("read_page", lambda m, b: m.read_page(b.redir)),
        ("extract_page", lambda m, b: m.extract_page(b.redir)),
        ("get_page_html", lambda m, b: m.get_page_html(b.redir)),
        ("extract_document", lambda m, b: m.extract_document(b.redir)),
        ("page_elements", lambda m, b: m.page_elements(b.redir)),
        ("evaluate_js", lambda m, b: m.evaluate_js("document.body ? document.body.innerText : ''", b.redir)),
        ("click_button", lambda m, b: m.click_button("absent", url=b.redir)),
        ("fill_field", lambda m, b: m.fill_field("input[name=q]", "x", url=b.redir)),
        ("wait_for", lambda m, b: m.wait_for("body", url=b.redir, timeout_ms=2000)),
        ("get_cookies", lambda m, b: m.get_cookies(b.redir)),
        ("detect_waf", lambda m, b: m.detect_waf(b.redir)),
        ("solve_captcha", lambda m, b: m.solve_captcha(b.redir)),
        ("screenshot_page", lambda m, b: m.screenshot_page(b.redir, path="shot.png")),
        ("save_page", lambda m, b: m.save_page(b.redir, "saved.html", format="html")),
        ("download_file", lambda m, b: m.download_file(b.redir, "loot.html")),
        ("download_file_chain", lambda m, b: m.download_file(b.chain, "loot-chain.html")),
        ("download_file_link_local", lambda m, b: m.download_file(b.redir_link, "loot-link.html")),
        ("crawl_site", lambda m, b: m.crawl_site(b.redir, depth=1, max_pages=3)),
        ("crawl_site_chain", lambda m, b: m.crawl_site(b.chain, depth=1, max_pages=3)),
        ("recon_site_apis", lambda m, b: m.recon_site_apis(b.redir, duration=1.0)),
        ("run_browser_task", lambda m, b: m.run_browser_task(
            "click_by_text", b.redir, {"text": "absent"})),
    ]


@pytest.mark.parametrize(
    "name,invoke",
    _navigation_cases(),
    ids=[name for name, _invoke in _navigation_cases()],
)
async def test_redirect_to_internal_is_not_fetched(harness: _Harness, name: str, invoke) -> None:
    start = len(harness.hits)
    files_before = {p for p in harness.write_dir.rglob("*") if p.is_file()}
    result = await invoke(harness.module, harness)
    fresh = harness.hits[start:]
    public = [hit for hit in fresh if hit[0] == PUBLIC_IP]
    assert public, (
        f"{name} never requested the supplied public URL, so this run did not "
        f"exercise navigation: {result!r:.400}"
    )
    reached = harness.internal_hits_since(start)
    assert reached == [], f"{name} requested an internal address: {reached} result={result!r:.400}"
    assert MARKER not in repr(result)
    files_after = {p for p in harness.write_dir.rglob("*") if p.is_file()}
    created = files_after - files_before
    assert created == set(), f"{name} created {created} while fetching an internal redirect"


async def test_crawl_same_origin_link_that_redirects_internally(harness: _Harness) -> None:
    """A link on the public page points at the same host, which then redirects internally."""
    start = len(harness.hits)
    result = await harness.module.crawl_site(harness.hub, depth=2, max_pages=5)
    assert any(hit[0] == PUBLIC_IP for hit in harness.hits[start:]), (
        f"crawl never requested the public page: {result!r:.400}"
    )
    reached = harness.internal_hits_since(start)
    assert reached == [], f"crawl followed a discovered redirect: {reached} result={result!r:.400}"
    assert MARKER not in repr(result)
    assert LOOP_IP not in repr(result.get("sitemap", ""))
    assert LINK_IP not in repr(result.get("sitemap", ""))
