"""SSRF regression: cloud metadata addresses must never be requested.

The MCP navigation tools guard URLs in ``mcp/server.py`` (``_ip_blocked`` /
``_check_url``) and then hand the same URL to Tilion, which navigates the
browser (``Tilion._session`` / ``Tab.goto`` → CDP ``Page.navigate``).

These tests fail while Oracle Cloud metadata ``192.0.0.192`` or the Azure
wire server ``168.63.129.16`` can pass that guard and reach navigation.
They pass once every navigation tool refuses those addresses before any
browser request or file write.

The CDP session here is a stand-in only for the bytes on the wire. ``Tab.goto``
itself is the real method from tilion 0.1.12 (the release current when this
server was committed): it sends ``Page.navigate`` with the URL argument
unchanged (``tilion/core/tab.py`` line 217). Nothing in this stand-in opens a
socket to those addresses.

Not covered, because the caller cannot supply a navigation URL:
``search_web``, ``press_key``, ``current_page``, ``list_browser_tasks``,
``list_tabs``, ``close_tab``, ``save_profile``, ``load_profile``,
``get_egress_info``, ``get_stealth_cdp_endpoint``.
"""
from __future__ import annotations

import asyncio
import importlib.util
import inspect
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SERVER_PATH = REPO / "mcp" / "server.py"
SENTINEL = "CLOUD-METADATA-BODY-SENTINEL"

# Literal addresses the guard must refuse. Variants still parse to the same host.
AZURE_URLS = [
    "http://168.63.129.16/",
    "http://168.63.129.16:80/machine/?comp=goalstate",
    "http://reader@168.63.129.16/metadata",
    "http://[::ffff:168.63.129.16]/",
    "http://168.63.129.16./",
]
ORACLE_URLS = [
    "http://192.0.0.192/",
    "http://192.0.0.192/opc/v2/instance/",
    "http://[::ffff:192.0.0.192]/",
    "http://192.0.0.192./",
]
BLOCKED_CONTROLS = [
    "http://127.0.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost/",
    "http://metadata.google.internal/",
    "http://metadata.google.internal./",
]
PUBLIC_URL = "http://example.com/"


def _load_server():
    """Load this repo's mcp/server.py without the repo directory shadowing the
    installed MCP SDK (the repo has a top-level ``mcp/`` package)."""
    repo = str(REPO)
    saved_path = list(sys.path)
    saved_mcp = {name: sys.modules[name] for name in list(sys.modules)
                 if name == "mcp" or name.startswith("mcp.")}
    sys.path = [p for p in sys.path if p not in ("", repo)]
    for name in saved_mcp:
        sys.modules.pop(name, None)
    try:
        spec = importlib.util.spec_from_file_location(
            "fortress_mcp_server_under_test", SERVER_PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path = saved_path
        # Keep the SDK's mcp package imported; do not restore the repo shadow.


@pytest.fixture(scope="module")
def mcp_server():
    os.environ.pop("TILION_ALLOW_PRIVATE_EGRESS", None)
    os.environ.pop("TILLION_ALLOW_PRIVATE_EGRESS", None)
    os.environ.pop("TILION_MCP_ALLOW_ANY_PATH", None)
    os.environ.pop("TILLION_MCP_ALLOW_ANY_PATH", None)
    write_root = tempfile.mkdtemp(prefix="tilion-mcp-ssrf-")
    os.environ["TILION_MCP_WRITE_DIR"] = write_root
    os.environ["TILLION_MCP_WRITE_DIR"] = write_root
    module = _load_server()
    yield module
    shutil.rmtree(write_root, ignore_errors=True)


class _Session:
    """Records CDP commands. ``Page.navigate`` is how Tab.goto requests a URL."""

    def __init__(self, log: list):
        self.log = log

    def send(self, method, params=None):
        self.log.append((method, params))

        async def _done():
            return {"frameId": "main"}

        return _done()

    async def on(self, event, callback):
        return None

    async def off(self, event, callback):
        return None


class _Browser:
    def __init__(self):
        from tilion.core.tab import Tab

        self.Tab = Tab
        self.log: list = []
        self.tabs: list = []
        self.is_started = True

    async def new_tab(self, url=None):
        tab = self.Tab.__new__(self.Tab)
        tab._closed = False
        tab._current_url = None
        tab._last_response = None
        session = _Session(self.log)

        async def _ensure_session():
            return session

        async def _navigate_await(nav_coro, url_for_error, wait_for, timeout):
            if inspect.isawaitable(nav_coro):
                await nav_coro

        async def evaluate(expression):
            text = str(expression)
            if "length" in text:
                return len(SENTINEL)
            if "querySelectorAll" in text:
                return {"buttons": [], "links": [], "fields": [], "headings": []}
            if "title" in text:
                return "meta"
            return SENTINEL

        async def content():
            return f"<html><title>meta</title><body>{SENTINEL}</body></html>"

        async def current_url():
            return tab._current_url or ""

        async def wait_for_idle(timeout=0):
            return None

        async def wait_for_timeout(ms=0):
            return None

        async def wait_for_selector(selector, timeout=0):
            return True

        async def screenshot():
            return SENTINEL.encode()

        async def save(path, format="pdf"):
            self.log.append(("save", path))
            Path(path).write_text(SENTINEL)

        async def download_url(target, dest):
            self.log.append(("download_url", target, dest))
            Path(dest).write_text(SENTINEL)

            class _Download:
                size_bytes = len(SENTINEL)

            return _Download()

        async def extract(**kwargs):
            class _Table:
                def to_dict_list(self):
                    return []

            class _Meta:
                title = "meta"

            class _Result:
                markdown = SENTINEL
                text = SENTINEL
                html = f"<p>{SENTINEL}</p>"
                tables = []
                metadata = _Meta()
                source_url = tab._current_url
                word_count = 1
                content_type = "text/html"
                extraction_method = "browser"
                confidence = 1
                structured = {}

            return _Result()

        async def get_cookies():
            return [{"name": "metadata", "value": SENTINEL}]

        async def index(**kwargs):
            class _Doc:
                url = tab._current_url
                title = SENTINEL
                type = "html"
                size_bytes = len(SENTINEL)

            class _Index:
                pages = [tab._current_url]
                documents = [_Doc()]
                stats = {}

                def get_sitemap(self):
                    return SENTINEL

            return _Index()

        async def fill(field, value):
            return None

        async def focus(field):
            return None

        async def press(key):
            return None

        async def click(selector):
            return None

        async def close():
            tab._closed = True

        tab._ensure_session = _ensure_session
        tab._session = session
        tab._navigate_await = _navigate_await
        tab.evaluate = evaluate
        tab.content = content
        tab.url = current_url
        tab.wait_for_idle = wait_for_idle
        tab.wait_for_timeout = wait_for_timeout
        tab.wait_for_selector = wait_for_selector
        tab.screenshot = screenshot
        tab.save = save
        tab.download_url = download_url
        tab.extract = extract
        tab.get_cookies = get_cookies
        tab.index = index
        tab.fill = fill
        tab.focus = focus
        tab.press = press
        tab.click = click
        tab.close = close
        self.tabs.append(tab)
        if url:
            await tab.goto(url, resolve_challenges=False)
        return tab

    async def visit(self, url):
        self.log.append(("visit", url))
        tab = await self.new_tab()
        await tab.goto(url)
        return tab


def _install_task_stub():
    import agent_tasks

    async def run_task(task, **kwargs):
        run_task.calls.append((task, kwargs))

        class _Result:
            ok = True
            data = None

            def to_dict(self):
                return {"task": task, "ok": True}

        return _Result()

    run_task.calls = []
    agent_tasks.run_task = run_task


async def _drive(module, invoke):
    """Point the server's shared browser at a real Tilion whose Tab.goto is real."""
    from tilion.facade import Tilion

    _install_task_stub()
    browser = _Browser()
    tilion = Tilion()
    tilion._started = True
    tilion._browser = browser
    tilion._pages_lock = asyncio.Lock()

    async def _t():
        return tilion

    module._t = _t
    module._tilion = tilion
    result = await invoke()
    return result, browser.log


def _metadata_navigations(log) -> list:
    hits = []
    for item in log:
        text = json.dumps(item, default=str)
        if "168.63.129.16" in text or "192.0.0.192" in text:
            hits.append(item)
    return hits


def _assert_refused(result, log, write_root: Path, label: str) -> None:
    hits = _metadata_navigations(log)
    rendered = json.dumps(result, default=str)
    written = [p for p in write_root.rglob("*") if p.is_file() and SENTINEL in p.read_text(errors="ignore")]
    assert not hits, f"{label} requested a metadata address: {hits}"
    assert SENTINEL not in rendered, f"{label} returned a metadata response body"
    assert not written, f"{label} wrote a file before refusing: {written}"
    assert isinstance(result, dict), label
    assert result.get("status") == "error", f"{label} did not refuse, got {result!r}"
    error = str(result.get("error", "")).lower()
    assert "refus" in error or "private" in error or "metadata" in error, result


def _clear_writes():
    root = Path(os.environ["TILION_MCP_WRITE_DIR"])
    if root.exists():
        for child in root.iterdir():
            if child.is_file():
                child.unlink()
            else:
                shutil.rmtree(child)
    return root


async def _call(module, name, url):
    if name == "fetch_protected_page":
        return await module.fetch_protected_page(url)
    if name == "run_browser_task":
        return await module.run_browser_task("extract_table", url, {})
    if name == "extract_page":
        return await module.extract_page(url)
    if name == "crawl_site":
        return await module.crawl_site(url, depth=1, max_pages=1)
    if name == "recon_site_apis":
        return await module.recon_site_apis(url, duration=1.0)
    if name == "screenshot_page":
        return await module.screenshot_page(url, path="shot.png")
    if name == "save_page":
        return await module.save_page(url, "page.pdf", format="pdf")
    if name == "read_page":
        return await module.read_page(url)
    if name == "page_elements":
        return await module.page_elements(url)
    if name == "click_button":
        return await module.click_button("continue", url=url)
    if name == "fill_field":
        return await module.fill_field("input[name=q]", "x", url=url)
    if name == "extract_document":
        return await module.extract_document(url)
    if name == "get_page_html":
        return await module.get_page_html(url)
    if name == "evaluate_js":
        return await module.evaluate_js("document.title", url=url)
    if name == "wait_for":
        return await module.wait_for("body", url=url, timeout_ms=500)
    if name == "download_file":
        return await module.download_file(url, "payload.bin")
    if name == "get_cookies":
        return await module.get_cookies(url)
    if name == "detect_waf":
        return await module.detect_waf(url)
    if name == "solve_captcha":
        return await module.solve_captcha(url)
    raise AssertionError(name)


NAV_TOOLS = [
    "fetch_protected_page",
    "run_browser_task",
    "extract_page",
    "crawl_site",
    "recon_site_apis",
    "screenshot_page",
    "save_page",
    "read_page",
    "page_elements",
    "click_button",
    "fill_field",
    "extract_document",
    "get_page_html",
    "evaluate_js",
    "wait_for",
    "download_file",
    "get_cookies",
    "detect_waf",
    "solve_captcha",
]


def test_ip_guard_refuses_metadata_literals(mcp_server):
    """The guard itself must reject the addresses, not only a later hop."""
    async def check(url):
        try:
            await mcp_server._check_url(url)
        except ValueError as exc:
            if "refus" in str(exc).lower():
                return None
            return f"{url} raised {exc}"
        return url

    allowed = [item for item in (asyncio.run(check(url))
                                 for url in AZURE_URLS + ORACLE_URLS + BLOCKED_CONTROLS)
               if item]
    assert allowed == [], f"guard allowed metadata targets: {allowed}"


def test_ip_guard_still_allows_a_public_host(mcp_server):
    async def check():
        await mcp_server._check_url(PUBLIC_URL)

    asyncio.run(check())


@pytest.mark.parametrize("url", AZURE_URLS + ORACLE_URLS)
def test_fetch_does_not_navigate_to_metadata(mcp_server, url):
    async def invoke():
        return await _drive(
            mcp_server, lambda: mcp_server.fetch_protected_page(url))

    root = _clear_writes()
    result, log = asyncio.run(invoke())
    _assert_refused(result, log, root, url)


@pytest.mark.parametrize("tool", NAV_TOOLS)
def test_every_navigation_tool_refuses_azure_wire_server(mcp_server, tool):
    url = "http://168.63.129.16/machine/?comp=goalstate"
    root = _clear_writes()

    async def invoke():
        return await _drive(mcp_server, lambda: _call(mcp_server, tool, url))

    result, log = asyncio.run(invoke())
    _assert_refused(result, log, root, tool)


@pytest.mark.parametrize("tool", ["fetch_protected_page", "download_file", "save_page", "extract_document"])
def test_oracle_metadata_is_not_requested(mcp_server, tool):
    url = "http://192.0.0.192/opc/v2/instance/"
    root = _clear_writes()

    async def invoke():
        return await _drive(mcp_server, lambda: _call(mcp_server, tool, url))

    result, log = asyncio.run(invoke())
    _assert_refused(result, log, root, tool)


def test_task_params_cannot_carry_a_metadata_url(mcp_server):
    """run_browser_task checks URL-looking params with the same guard."""
    root = _clear_writes()
    metadata = "http://168.63.129.16/"

    async def invoke():
        return await _drive(
            mcp_server,
            lambda: mcp_server.run_browser_task(
                "extract_table", PUBLIC_URL, {"next": metadata}))

    result, log = asyncio.run(invoke())
    import agent_tasks
    forwarded = json.dumps(getattr(agent_tasks.run_task, "calls", []), default=str)
    assert "168.63.129.16" not in forwarded, forwarded
    _assert_refused(result, log, root, "run_browser_task params")


def test_public_fetch_still_navigates(mcp_server):
    async def invoke():
        return await _drive(
            mcp_server, lambda: mcp_server.fetch_protected_page(PUBLIC_URL))

    result, log = asyncio.run(invoke())
    navigated = [item for item in log if item[0] == "Page.navigate"]
    assert navigated, log
    assert any(PUBLIC_URL == (item[1] or {}).get("url") for item in navigated), navigated
    assert isinstance(result, dict)
    assert result.get("status") != "error" or "refus" not in str(result.get("error", "")).lower()


def test_refused_download_creates_no_file(mcp_server):
    root = _clear_writes()
    url = "http://168.63.129.16/machine/?comp=goalstate"

    async def invoke():
        return await _drive(
            mcp_server, lambda: mcp_server.download_file(url, "secret.bin"))

    result, log = asyncio.run(invoke())
    _assert_refused(result, log, root, "download_file")
    assert list(root.rglob("*")) == []
