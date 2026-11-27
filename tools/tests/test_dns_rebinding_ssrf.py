"""DNS-rebinding SSRF through the MCP URL guard.

The guard in ``mcp/server.py`` resolves a hostname once and, when every answer
is public, passes that same hostname to the browser. The browser resolves it
again. These tests run that path: a name whose glibc answers stay public (so
``_check_url`` and any extra ``getaddrinfo`` between the check and the
navigation both allow it) while Chromium, which asks on its own and also sends
an HTTPS-RR query that glibc does not, is answered with a loopback or
link-local address.

They fail while the tool still connects to that second address or returns its
body. They pass once navigation is pinned to an address that passed the check,
or the connect-time resolution is aborted when any new answer is internal.

Run from a normal shell (the module enters a user network namespace so its DNS
server is the only resolver):

    python3 -m pytest tools/tests/test_dns_rebinding_ssrf.py -q

Not covered here, because they do not take a caller-supplied host through
``_check_url`` and then navigate:

* ``search_web`` — the argument is a query string
* ``get_egress_info`` — fetches a fixed host and does not call ``_check_url``
* ``press_key``, ``current_page``, ``list_tabs``, ``close_tab``,
  ``save_profile``, ``load_profile``, ``list_browser_tasks``,
  ``get_stealth_cdp_endpoint`` — no target URL
* ``click_button``, ``fill_field``, ``evaluate_js``, ``wait_for``,
  ``get_cookies``, ``detect_waf``, ``solve_captcha`` when ``url`` is omitted —
  they act on the page already open

``download_file`` is covered. The shipped ``Tilion.download``
(``tilion/core/tab.py`` ``download_url``) fetches with ``aiohttp`` after the
guard, which is the same check-then-resolve gap; the double below still
performs the independent browser resolution the finding describes, so an extra
``getaddrinfo`` in front of that fetch does not hide it.
"""
from __future__ import annotations

import atexit
import asyncio
import base64
import hashlib
import importlib.util
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

import pytest

# Re-exec inside a user netns before any resolver cache or pytest fixture runs,
# so both glibc and Chromium use the DNS server this file binds to 127.0.0.1:53.
def _undo_pytest_capture() -> None:
    """Give the re-exec'd process the stdio pytest's FD capture replaced.

    Collection imports this module after pytest has dup'd fd 1 and 2 onto
    deleted temp files. ``os.execvp`` keeps those fds, so the namespace's
    pytest would write into a pipe nobody reads. The originals are still open
    on higher fds; put them back first.
    """
    def link(fd: int) -> str:
        try:
            return os.readlink(f"/proc/self/fd/{fd}")
        except OSError:
            return ""

    captured = {link(1), link(2)}
    if not any("(deleted)" in t for t in captured):
        return
    originals = []
    for fd in range(3, 64):
        target = link(fd)
        if (not target or target in captured or "(deleted)" in target
                or target == "/dev/null"):
            continue
        if target not in [item[1] for item in originals]:
            originals.append((fd, target))
    if not originals:
        return
    os.dup2(originals[0][0], 1)
    os.dup2(originals[-1][0], 2)


if os.environ.get("FORTRESS_REBIND_NS") != "1":
    _undo_pytest_capture()
    os.environ["FORTRESS_REBIND_NS"] = "1"
    argv = " ".join(
        __import__("shlex").quote(a) for a in (sys.executable, *sys.argv)
    )
    cwd = __import__("shlex").quote(os.getcwd())
    script = f"""
set -e
export PATH=/usr/sbin:/usr/bin:$PATH
export FORTRESS_REBIND_NS=1
export PYTHONUNBUFFERED=1
ip link set lo up
ip addr add 169.254.169.254/32 dev lo
printf 'nameserver 127.0.0.1\\n' > /tmp/fortress-rebind-resolv.conf
mount --bind /tmp/fortress-rebind-resolv.conf /etc/resolv.conf
cd {cwd}
exec {argv}
"""
    os.execvp(
        "unshare",
        ["unshare", "--user", "--map-root-user", "--net", "--mount", "bash", "-c", script],
    )

MARKER = "INTERNAL_BODY_MARKER"
PUBLIC_IP = "8.8.8.8"  # global; _ip_blocked() is false for it
LOOPBACK = "127.0.0.1"
METADATA = "169.254.169.254"

_REPO = Path(__file__).resolve().parents[2]
_REPO_SERVER = _REPO / "mcp" / "server.py"


def _load_server():
    """Load the repo's mcp/server.py against the installed MCP SDK.

    Pytest puts the repo root on sys.path, and this repo's ``mcp/`` package
    then shadows the SDK's ``mcp`` package. ``server.py`` imports
    ``mcp.server.fastmcp`` from the SDK, so that import has to be bound first.
    """
    os.environ.setdefault("TILION_MCP_PREWARM", "0")
    os.environ.pop("TILION_ALLOW_PRIVATE_EGRESS", None)
    os.environ.pop("TILLION_ALLOW_PRIVATE_EGRESS", None)
    repo = _REPO.resolve()
    saved_path = sys.path[:]
    sys.path = [
        p for p in sys.path
        if Path(p or os.getcwd()).resolve() != repo
    ]
    for name in list(sys.modules):
        if name == "mcp" or name.startswith("mcp."):
            # Drop a partially imported local mcp/ so the SDK can take the name.
            mod = sys.modules[name]
            origin = getattr(mod, "__file__", "") or ""
            if origin.startswith(str(repo)):
                del sys.modules[name]
    import mcp.server.fastmcp  # noqa: F401  (the SDK)
    import mcp.types  # noqa: F401
    sys.path = saved_path
    spec = importlib.util.spec_from_file_location("repo_mcp_server", _REPO_SERVER)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SERVER = _load_server()


# --- DNS: public for every glibc lookup, internal once Chromium asks --------

def _encode_name(name: str) -> bytes:
    out = b""
    for part in name.rstrip(".").split("."):
        raw = part.encode()
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def _parse_name(data: bytes, off: int) -> tuple[str, int]:
    labels = []
    for _ in range(64):
        n = data[off]
        if n == 0:
            return ".".join(labels), off + 1
        if n & 0xC0:
            raise ValueError("compressed name in question")
        off += 1
        labels.append(data[off:off + n].decode())
        off += n
    raise ValueError("name too long")


class _Dns:
    """Authoritative answers for ``*.rebind.test``.

    A/AAAA queries are the ones ``getaddrinfo`` sends. Chromium's stub resolver
    also sends type 65 (HTTPS RR) for the name it is about to connect to; glibc
    does not. A answers stay at ``PUBLIC_IP`` until that HTTPS query is seen for
    the same name, then they switch to the internal address. An extra
    ``getaddrinfo`` between the guard and navigation therefore still looks
    public, and the browser's own lookup does not.
    """

    def __init__(self):
        self.internal = {}  # hostname -> dotted IPv4
        self.https_seen = set()
        self.log = []
        self._pending = []
        self._lock = threading.Lock()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 53))
        self._sock.settimeout(0.02)
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def arm(self, host: str, internal: str) -> None:
        with self._lock:
            self.internal[host.rstrip(".").lower()] = internal

    def _reply(self, addr, tid, rd, question, answers: bytes, ancount: int) -> None:
        flags = 0x8400 | rd | 0x0080  # QR, AA, RA, RD copied
        self._sock.sendto(
            tid + struct.pack("!HHHHH", flags, 1, ancount, 0, 0) + question + answers,
            addr,
        )

    def _loop(self) -> None:
        while True:
            now = time.monotonic()
            due = []
            with self._lock:
                keep = []
                for item in self._pending:
                    (due if item[0] <= now else keep).append(item)
                self._pending = keep
            for _when, tid, rd, question, qname, addr in due:
                with self._lock:
                    chrome = qname in self.https_seen
                    internal = self.internal.get(qname, LOOPBACK)
                ip = internal if chrome else PUBLIC_IP
                packed = socket.inet_aton(ip)
                ans = _encode_name(qname) + struct.pack("!HHIH", 1, 1, 0, 4) + packed
                self._reply(addr, tid, rd, question, ans, 1)
                self.log.append(f"A {qname} -> {ip}")
            try:
                data, addr = self._sock.recvfrom(4096)
            except socket.timeout:
                continue
            tid = data[:2]
            flags = struct.unpack("!H", data[2:4])[0]
            rd = flags & 0x0100
            try:
                qname, off = _parse_name(data, 12)
                qtype, _qclass = struct.unpack("!HH", data[off:off + 4])
            except Exception:
                continue
            qname = qname.lower()
            question = data[12:off + 4]
            tracked = qname in self.internal or qname.endswith(".rebind.test")
            if tracked and qtype == 65:
                with self._lock:
                    self.https_seen.add(qname)
                self.log.append(f"HTTPS {qname}")
                self._reply(addr, tid, rd, question, b"", 0)
                continue
            if tracked and qtype == 1:
                # Answer after the parallel HTTPS query has been read.
                with self._lock:
                    self._pending.append(
                        (time.monotonic() + 0.15, tid, rd, question, qname, addr)
                    )
                continue
            self._reply(addr, tid, rd, question, b"", 0)


DNS = _Dns()


class _Handler(BaseHTTPRequestHandler):
    hits: list[tuple[str, str]] = []

    def do_GET(self):
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        _Handler.hits.append((host, self.path))
        body = MARKER.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


def _serve(ip: str) -> None:
    httpd = ThreadingHTTPServer((ip, 80), _Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()


_serve(LOOPBACK)
_serve(METADATA)


# --- Chromium, driven the way Tab.goto is: CDP Page.navigate {url} ----------

class _Chrome:
    def __init__(self):
        bin_ = shutil.which("google-chrome") or shutil.which("google-chrome-stable")
        if not bin_:
            raise RuntimeError("google-chrome is required to resolve the way the browser does")
        profile = f"/tmp/fortress-rebind-chrome-{uuid.uuid4().hex}"
        self._proc = subprocess.Popen(
            [
                bin_, "--headless=new", "--disable-gpu", "--no-sandbox",
                "--disable-dev-shm-usage", "--disable-features=DnsOverHttps",
                "--remote-debugging-port=9333", f"--user-data-dir={profile}",
                "--no-first-run", "about:blank",
            ],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        import urllib.request
        last = None
        for _ in range(50):
            try:
                with urllib.request.urlopen("http://127.0.0.1:9333/json/list", timeout=0.2) as r:
                    tabs = json.load(r)
                page = next(t for t in tabs if t.get("type") == "page")
                self._ws = page["webSocketDebuggerUrl"]
                break
            except Exception as exc:
                last = exc
                time.sleep(0.1)
        else:
            raise RuntimeError(f"chrome devtools did not come up: {last}")
        self._sock = self._connect(self._ws)
        self._id = 0
        self._lock = threading.Lock()
        atexit.register(self._proc.terminate)

    @staticmethod
    def _connect(url: str) -> socket.socket:
        u = urlparse(url)
        sock = socket.create_connection((u.hostname, u.port), timeout=5)
        key = base64.b64encode(os.urandom(16)).decode()
        sock.sendall(
            f"GET {u.path} HTTP/1.1\r\nHost: {u.hostname}:{u.port}\r\n"
            f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n".encode()
        )
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += sock.recv(4096)
        accept = base64.b64encode(
            hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
        ).decode()
        if accept.encode() not in buf:
            raise RuntimeError(f"websocket handshake rejected: {buf[:200]!r}")
        sock.settimeout(5)
        return sock

    def _send(self, payload: bytes, opcode: int = 0x1) -> None:
        mask = os.urandom(4)
        n = len(payload)
        hdr = bytes([0x80 | opcode])
        if n < 126:
            hdr += bytes([0x80 | n])
        elif n < 65536:
            hdr += bytes([0x80 | 126]) + struct.pack("!H", n)
        else:
            hdr += bytes([0x80 | 127]) + struct.pack("!Q", n)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self._sock.sendall(hdr + mask + masked)

    def _recv_frame(self) -> tuple[int, bytes]:
        def recvn(n):
            buf = b""
            while len(buf) < n:
                chunk = self._sock.recv(n - len(buf))
                if not chunk:
                    raise EOFError("chrome socket closed")
                buf += chunk
            return buf

        b0, b1 = recvn(2)
        ln = b1 & 0x7F
        if ln == 126:
            ln = struct.unpack("!H", recvn(2))[0]
        elif ln == 127:
            ln = struct.unpack("!Q", recvn(8))[0]
        data = recvn(ln)
        if b1 & 0x80:
            raise RuntimeError("unexpected masked frame from chrome")
        return b0 & 0x0F, data

    def _call(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        mid = self._id
        msg = {"id": mid, "method": method}
        if params:
            msg["params"] = params
        self._send(json.dumps(msg).encode())
        while True:
            opcode, data = self._recv_frame()
            if opcode == 0x9:  # ping
                self._send(data, opcode=0xA)
                continue
            if opcode == 0x8:
                raise EOFError("chrome closed the devtools socket")
            if opcode != 0x1 or not data:
                continue
            parsed = json.loads(data)
            if parsed.get("id") == mid:
                return parsed

    def navigate(self, url: str) -> str:
        """Page.navigate the URL string, then read the document text.

        This is the CDP call ``Tab.goto`` makes after the guard returns
        (``session.send('Page.navigate', {'url': url})``).
        """
        with self._lock:
            before = len(_Handler.hits)
            self._call("Page.navigate", {"url": url})
            deadline = time.monotonic() + 2.5
            text = ""
            while time.monotonic() < deadline:
                if len(_Handler.hits) > before:
                    time.sleep(0.05)
                    break
                time.sleep(0.05)
            try:
                ev = self._call(
                    "Runtime.evaluate",
                    {"expression": "document.body ? document.body.innerText : ''",
                     "returnByValue": True},
                )
                text = ((ev.get("result") or {}).get("result") or {}).get("value") or ""
            except Exception:
                text = ""
            return text


CHROME = _Chrome()


async def _facade_guard(url: str) -> None:
    """The second check ``Tilion._guard_url`` runs before ``page.goto``.

    ``tilion`` 0.1.16 ``netguard.host_blocked`` resolves with ``getaddrinfo``
    and caches an allow for ``TILION_NETGUARD_ALLOW_TTL_S`` (default 30s). It
    does not pin the address the browser will dial.
    """
    try:
        from tilion.core.engine import netguard
    except Exception:
        return
    parsed = urlparse(url)
    if await netguard.host_blocked(parsed.hostname or "", parsed.port or 0):
        raise PermissionError(f"netguard refused {parsed.hostname!r}")


class _Browser:
    """Stand-in for the Tilion methods the tools call.

    Each method that the real facade navigates does two things the shipped
    code does: ``netguard.host_blocked`` (``facade._guard_url`` / ``_session``),
    then CDP ``Page.navigate`` of the original URL string (``Tab.goto``).
    """

    async def _load(self, url: str | None) -> str:
        if not url:
            return ""
        await _facade_guard(url)
        return await asyncio.to_thread(CHROME.navigate, url)

    async def fetch(self, url, **_k):
        body = await self._load(url)
        return {"url": url, "status": "ok", "title": "", "text": body,
                "html": body, "blocked": False}

    async def extract(self, url, schema=None, **_k):
        body = await self._load(url)
        return {"url": url, "markdown": body, "text": body, "html": body, "title": ""}

    async def crawl(self, url, **_k):
        body = await self._load(url)
        return {"pages_crawled": 1, "document_count": 0, "documents": [],
                "text": body}

    async def recon(self, url, **_k):
        body = await self._load(url)
        return {"api_endpoints": [], "text": body}

    async def screenshot(self, url, path=None, **_k):
        body = await self._load(url)
        return {"url": url, "text": body, "png_base64": ""}

    async def save(self, url, path, format="html", **_k):
        body = await self._load(url)
        return {"path": path, "format": format, "text": body}

    async def read(self, url=None, **_k):
        body = await self._load(url)
        return {"url": url, "title": "", "markdown": body, "tables": []}

    async def elements(self, url=None, **_k):
        body = await self._load(url)
        return {"url": url, "buttons": [], "links": [], "fields": [],
                "headings": [], "text": body}

    async def click(self, text, url=None, **_k):
        body = await self._load(url)
        return {"clicked": text, "url": url, "title": body}

    async def fill(self, field, value, url=None, submit=False, **_k):
        body = await self._load(url)
        return {"filled": field, "submitted": submit, "url": url, "text": body}

    async def extract_url(self, url, **_k):
        body = await self._load(url)
        return {"url": url, "markdown": body, "text": body, "html": body}

    async def get_html(self, url, **_k):
        body = await self._load(url)
        return {"url": url, "html": body}

    async def evaluate(self, expression, url=None, **_k):
        body = await self._load(url)
        return {"result": body, "url": url}

    async def wait_for(self, selector, url=None, timeout_ms=10000, **_k):
        body = await self._load(url)
        return {"selector": selector, "found": True, "url": url, "text": body}

    async def download(self, url, dest, **_k):
        body = await self._load(url)
        return {"url": url, "path": dest, "bytes": len(body), "text": body}

    async def get_cookies(self, url=None, **_k):
        body = await self._load(url)
        return [{"name": "body", "value": body}]

    async def detect_waf(self, url=None, **_k):
        body = await self._load(url)
        return {"vendor": None, "text": body}

    async def solve_captcha(self, url=None, **_k):
        body = await self._load(url)
        return {"detected": False, "solved": False, "text": body}

    async def agent(self, task, url=None, **params):
        parts = []
        if url:
            parts.append(await self._load(url))
        for value in params.values():
            if isinstance(value, str) and value[:8].lower().startswith(("http://", "https://")):
                if value != url:
                    parts.append(await self._load(value))
        return {"task": task, "text": "\n".join(parts)}


@pytest.fixture
def browser(monkeypatch):
    inst = _Browser()

    async def _t():
        return inst

    monkeypatch.setattr(SERVER, "_t", _t)
    return inst


def _host(tag: str, internal: str = LOOPBACK) -> str:
    host = f"{tag}-{uuid.uuid4().hex[:8]}.rebind.test"
    DNS.arm(host, internal)
    return host


def _hits(host: str) -> list[tuple[str, str]]:
    return [h for h in _Handler.hits if h[0] == host]


def _assert_internal_not_reached(host: str, result) -> None:
    blob = json.dumps(result, default=str)
    reached = _hits(host)
    assert not reached, (
        f"{host} was fetched from the internal listener {reached}; "
        f"tool result={blob[:600]}"
    )
    assert MARKER not in blob, (
        f"{host} body was returned to the tool caller: {blob[:600]}"
    )


def _run(coro):
    return asyncio.run(coro)


# --- literals the guard already rejects (these pass on the current code) ----

@pytest.mark.parametrize("url", [
    "http://127.0.0.1/",
    "http://127.0.0.1:80/",
    "http://[::1]/",
    "http://169.254.169.254/",
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost/",
    "http://metadata.google.internal/",
    "http://10.1.2.3/",
    "http://192.168.0.1/",
])
def test_literal_internal_targets_are_refused(browser, url):
    before = len(_Handler.hits)
    result = _run(SERVER.fetch_protected_page(url))
    assert result.get("status") == "error"
    assert _Handler.hits[before:] == []
    assert MARKER not in json.dumps(result)


def test_repeated_getaddrinfo_stays_public(browser):
    """Lookups of the same kind as the guard keep seeing only the public answer.

    A fix that calls ``getaddrinfo`` once more between ``_check_url`` and the
    navigation still gets ``PUBLIC_IP`` and would still allow the URL. The
    browser lookup is the one that changes.
    """
    host = _host("repeat")
    for _ in range(4):
        infos = socket.getaddrinfo(host, 80)
        addrs = {item[4][0] for item in infos}
        assert addrs == {PUBLIC_IP}, addrs
        assert all(not SERVER._ip_blocked(addr) for addr in addrs)
    result = _run(SERVER.fetch_protected_page(f"http://{host}/marker"))
    _assert_internal_not_reached(host, result)


@pytest.mark.parametrize("tool", [
    "fetch_protected_page",
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
])
def test_navigation_tool_does_not_follow_rebind_to_loopback(browser, tool):
    host = _host(tool)
    url = f"http://{host}/from-{tool}"
    result = _run(_call_tool(tool, url))
    _assert_internal_not_reached(host, result)


def test_fetch_does_not_follow_rebind_to_metadata_address(browser):
    host = _host("metadata", METADATA)
    result = _run(SERVER.fetch_protected_page(f"http://{host}/latest/meta-data/"))
    _assert_internal_not_reached(host, result)


def test_task_url_and_param_url_do_not_rebind(browser):
    """``run_browser_task`` checks ``url`` and URL-shaped ``params`` then hands
    both to ``Tilion.agent``, which navigates to the original strings."""
    main = _host("task")
    extra = _host("param")
    result = _run(SERVER.run_browser_task(
        "navigate_spa",
        f"http://{main}/task",
        params={"next": f"http://{extra}/param", "limit": 1},
    ))
    _assert_internal_not_reached(main, result)
    _assert_internal_not_reached(extra, result)


async def _call_tool(tool: str, url: str):
    s = SERVER
    if tool == "fetch_protected_page":
        return await s.fetch_protected_page(url)
    if tool == "extract_page":
        return await s.extract_page(url)
    if tool == "crawl_site":
        return await s.crawl_site(url, depth=1, max_pages=1)
    if tool == "recon_site_apis":
        return await s.recon_site_apis(url, duration=1)
    if tool == "screenshot_page":
        return await s.screenshot_page(url, path="shot.png")
    if tool == "save_page":
        return await s.save_page(url, "page.html", format="html")
    if tool == "read_page":
        return await s.read_page(url)
    if tool == "page_elements":
        return await s.page_elements(url)
    if tool == "click_button":
        return await s.click_button("Go", url=url)
    if tool == "fill_field":
        return await s.fill_field("input[name=q]", "x", url=url)
    if tool == "extract_document":
        return await s.extract_document(url)
    if tool == "get_page_html":
        return await s.get_page_html(url)
    if tool == "evaluate_js":
        return await s.evaluate_js("document.body.innerText", url=url)
    if tool == "wait_for":
        return await s.wait_for("body", url=url, timeout_ms=1000)
    if tool == "download_file":
        return await s.download_file(url, "payload.bin")
    if tool == "get_cookies":
        return await s.get_cookies(url)
    if tool == "detect_waf":
        return await s.detect_waf(url)
    if tool == "solve_captcha":
        return await s.solve_captcha(url)
    raise AssertionError(tool)
