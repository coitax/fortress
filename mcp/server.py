"""The Fortress stealth-browser MCP server.

Tool descriptions are deliberately intent-loaded: they name the failure the agent
is experiencing (blocked, 403, Cloudflare, DataDome, PerimeterX, bot detection) so
the model selects this tool the moment a fetch/automation gets blocked.

One shared Tilion instance backs every tool (lazy-started on first use, closed at
process exit). Local mode by default; TILION_BASE_URL/TILION_API_KEY switch to the
hosted fleet.
"""
from __future__ import annotations

import asyncio
import contextvars
import functools
import os
import sys
from contextlib import asynccontextmanager

from mcp.server.fastmcp import Context, FastMCP
from mcp.types import ToolAnnotations

from tilion.facade import Tilion

# Tool safety hints (clients auto-approve reads, gate writes/destructive). Everything
# touches the live internet → openWorldHint; list_browser_tasks is pure-local.
_READ = ToolAnnotations(readOnlyHint=True, openWorldHint=True)
_LOCAL = ToolAnnotations(readOnlyHint=True, openWorldHint=False)
_WRITE = ToolAnnotations(readOnlyHint=False, openWorldHint=True)
_DESTRUCTIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=True, openWorldHint=True)


def _env(name: str, default: str | None = None) -> str | None:
    """Read a config var tolerant of BOTH brand prefixes during the migration:
    the new one-L `TILION_*` first, then the legacy two-L `TILLION_*` the server
    core still uses — so an operator isn't silently unconfigured across the
    facade/server boundary. (The arham->tilion rename unifies these.)"""
    return os.environ.get(f"TILION_{name}", os.environ.get(f"TILLION_{name}", default))


# Per-tool wall-clock cap: a hung nav/crawl must NOT wedge the shared browser (it
# holds a per-origin lock). On timeout the coroutine is cancelled (unwinding the
# lock) and a structured error is returned. Tune via env.
_TOOL_TIMEOUT = float(_env("MCP_TOOL_TIMEOUT", "120"))


def _safe(fn):
    """Error boundary for a tool: enforce a wall-clock timeout AND on any failure
    return a STRUCTURED error the agent can reason about ({status:'error', error})
    instead of an opaque protocol error, so a bad/slow call never crashes or wedges
    the server. Preserves the signature so FastMCP introspects it."""
    @functools.wraps(fn)
    async def wrap(*args, **kwargs):
        try:
            return await asyncio.wait_for(fn(*args, **kwargs), timeout=_TOOL_TIMEOUT)
        except asyncio.TimeoutError:
            return {"status": "error",
                    "error": f"tool timed out after {_TOOL_TIMEOUT:.0f}s "
                             f"(raise TILION_MCP_TOOL_TIMEOUT for slow crawls)"}
        except Exception as exc:  # noqa: BLE001 - deliberate catch-all at the tool boundary
            return {"status": "error", "error": f"{type(exc).__name__}: {exc}"}
    return wrap


def _ip_blocked(ip_str: str) -> bool:
    import ipaddress
    try:
        ip = ipaddress.ip_address(ip_str.split("%", 1)[0])
    except ValueError:
        return False
    if ip.version == 6:
        # IPv6 forms that carry an IPv4 destination are judged by that IPv4 address:
        # mapped (::ffff:a.b.c.d), NAT64 (64:ff9b::a.b.c.d) and 6to4 (2002:aabb:ccdd::).
        if ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        elif ip in ipaddress.ip_network("64:ff9b::/96"):
            ip = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        elif ip.sixtofour is not None:
            ip = ip.sixtofour
    return (not ip.is_global or ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


class _EgressRefused(PermissionError):
    pass


def _private_egress_allowed() -> bool:
    return _env("ALLOW_PRIVATE_EGRESS", "0") == "1"


async def _resolve_public(host: str, port: int) -> list[tuple[int, str]]:
    """Resolve ``host`` ONCE and return the (family, address) pairs a connection may
    use. Raises _EgressRefused if the host is a blocked name or ANY address is
    internal. Callers must connect to exactly the returned addresses — never resolve
    the name again — so a DNS answer that changes between check and connect (DNS
    rebinding) cannot reach an internal address.

    DNS resolution goes through the event loop's ASYNC resolver — a blocking
    socket.getaddrinfo here would stall every concurrent tool call and could not
    be cancelled by the per-tool timeout."""
    import ipaddress
    import socket

    host = (host or "").strip().strip("[]")
    if not host:
        raise _EgressRefused("refused empty host")
    try:
        literal = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        literal = None
    allow = _private_egress_allowed()
    if literal is not None:
        if not allow and _ip_blocked(host):
            raise _EgressRefused(f"refused private/internal address {host!r} "
                                 "(set TILION_ALLOW_PRIVATE_EGRESS=1 to allow)")
        fam = socket.AF_INET6 if literal.version == 6 else socket.AF_INET
        return [(fam, host)]
    if not allow and host.lower().rstrip(".") in ("localhost", "metadata.google.internal"):
        raise _EgressRefused(f"refused private/metadata host {host!r} "
                             "(set TILION_ALLOW_PRIVATE_EGRESS=1 to allow)")
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port or None, type=socket.SOCK_STREAM)
    out: list[tuple[int, str]] = []
    for family, _type, _proto, _canon, sockaddr in infos:
        addr = sockaddr[0]
        if not allow and _ip_blocked(addr):
            raise _EgressRefused(f"refused private/internal address for {host!r} "
                                 "(set TILION_ALLOW_PRIVATE_EGRESS=1 to allow)")
        if (family, addr) not in out:
            out.append((family, addr))
    if not out:
        raise OSError(f"no addresses for {host!r}")
    return out


async def _check_url(url: str) -> None:
    """Early, readable refusal of a caller-supplied localhost / private /
    cloud-metadata URL unless the operator opts in with
    TILION_ALLOW_PRIVATE_EGRESS=1. This only covers the first hop; every
    connection the browser or a download makes (redirects, crawled links,
    sub-resources) is enforced separately by _EgressGuard / _GuardedHTTP."""
    if _private_egress_allowed():
        return
    from urllib.parse import urlparse

    host = (urlparse(url).hostname or "").strip("[]")
    if not host:
        raise ValueError(f"invalid url: {url!r}")
    try:
        await _resolve_public(host, 0)
    except _EgressRefused as exc:
        raise ValueError(str(exc)) from None
    except Exception:
        return  # unresolvable → let the browser surface a clean nav error


# ── egress enforcement on every hop ──────────────────────────────────────────
# The browser follows redirects, crawled links and sub-resource loads on its own,
# and the facade's downloaders follow redirects inside aiohttp, so checking the
# caller's URL is not enough. Every TCP connection the stealth browser opens goes
# through _EgressGuard (a loopback-only SOCKS5 relay), and every in-process HTTP
# fetch of a caller-influenced URL goes through _GuardedHTTP. Both resolve each
# destination once with _resolve_public and connect to exactly those addresses.

_SOCKS_OK, _SOCKS_RULESET, _SOCKS_UNREACHABLE = 0, 2, 4
_SOCKS_REFUSED, _SOCKS_BAD_CMD, _SOCKS_BAD_ATYP = 5, 7, 8


class _EgressGuard:
    """SOCKS5 relay on 127.0.0.1 that the stealth browser is launched behind (with
    loopback NOT bypassed). Each CONNECT is resolved once, refused if any address is
    internal, and relayed to the validated address — directly, or through the
    operator's TILION_PROXY via an HTTP CONNECT to that same address."""

    def __init__(self, upstream=None) -> None:
        self._upstream = upstream
        self._server: asyncio.AbstractServer | None = None
        self._conns: set[asyncio.Task] = set()
        self.loop: asyncio.AbstractEventLoop | None = None
        self.port = 0

    async def start(self) -> None:
        self.loop = asyncio.get_running_loop()
        self._server = await asyncio.start_server(self._accept, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]

    def browser_args(self, host: str) -> list[str]:
        return [f"--proxy-server=socks5://{host}:{self.port}",
                "--proxy-bypass-list=<-loopback>"]

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            self._server = None
        for task in list(self._conns):
            task.cancel()
        self._conns.clear()

    async def _accept(self, reader, writer) -> None:
        task = asyncio.current_task()
        self._conns.add(task)
        try:
            await self._serve(reader, writer)
        except (asyncio.CancelledError, Exception):
            pass
        finally:
            self._conns.discard(task)
            writer.close()

    @staticmethod
    async def _reply(writer, code: int) -> None:
        writer.write(bytes([5, code, 0, 1, 0, 0, 0, 0, 0, 0]))
        await writer.drain()

    async def _serve(self, reader, writer) -> None:
        import socket

        ver, nmethods = await asyncio.wait_for(reader.readexactly(2), 30)
        if ver != 5:
            return
        methods = await reader.readexactly(nmethods)
        if 0 not in methods:
            writer.write(b"\x05\xff")
            await writer.drain()
            return
        writer.write(b"\x05\x00")
        await writer.drain()
        ver, cmd, _rsv, atyp = await asyncio.wait_for(reader.readexactly(4), 30)
        if atyp == 1:
            host = socket.inet_ntop(socket.AF_INET, await reader.readexactly(4))
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
        elif atyp == 3:
            n = (await reader.readexactly(1))[0]
            host = (await reader.readexactly(n)).decode("ascii", "replace")
        else:
            await self._reply(writer, _SOCKS_BAD_ATYP)
            return
        port = int.from_bytes(await reader.readexactly(2), "big")
        if ver != 5 or cmd != 1:
            await self._reply(writer, _SOCKS_BAD_CMD)
            return
        try:
            addrs = await _resolve_public(host, port)
        except _EgressRefused:
            await self._reply(writer, _SOCKS_RULESET)
            return
        except Exception:
            await self._reply(writer, _SOCKS_UNREACHABLE)
            return
        try:
            up_reader, up_writer = await self._open(addrs, port)
        except Exception:
            await self._reply(writer, _SOCKS_REFUSED)
            return
        try:
            await self._reply(writer, _SOCKS_OK)
            await self._relay(reader, writer, up_reader, up_writer)
        finally:
            up_writer.close()

    async def _open(self, addrs: list[tuple[int, str]], port: int):
        last: Exception | None = None
        for _family, addr in addrs:
            try:
                if self._upstream is None:
                    return await asyncio.wait_for(asyncio.open_connection(addr, port), 15)
                return await asyncio.wait_for(self._open_upstream(addr, port), 30)
            except Exception as exc:  # noqa: BLE001 - try the next validated address
                last = exc
        raise last or OSError("no address")

    async def _open_upstream(self, addr: str, port: int):
        import base64

        up = self._upstream
        r, w = await asyncio.open_connection(up.host, int(up.port))
        target = f"[{addr}]:{port}" if ":" in addr else f"{addr}:{port}"
        head = f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n"
        if up.username:
            token = base64.b64encode(
                f"{up.username}:{up.password or ''}".encode()).decode()
            head += f"Proxy-Authorization: Basic {token}\r\n"
        w.write((head + "\r\n").encode())
        await w.drain()
        resp = await r.readuntil(b"\r\n\r\n")
        status = resp.split(b"\r\n", 1)[0].split()
        if len(status) < 2 or status[1] != b"200":
            w.close()
            raise OSError(f"upstream proxy refused CONNECT: {resp[:80]!r}")
        return r, w

    @staticmethod
    async def _relay(r1, w1, r2, w2) -> None:
        async def pipe(src, dst):
            while True:
                data = await src.read(65536)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
            if dst.can_write_eof():
                dst.write_eof()

        tasks = {asyncio.create_task(pipe(r1, w2)), asyncio.create_task(pipe(r2, w1))}
        try:
            await asyncio.wait(tasks, return_when=asyncio.FIRST_EXCEPTION)
        finally:
            for task in tasks:
                task.cancel()


_guard: _EgressGuard | None = None


def _strip_proxy_flags(args: list[str]) -> list[str]:
    drop = ("--proxy-server", "--proxy-bypass-list", "--proxy-pac-url",
            "--no-proxy-server", "--proxy-auto-detect", "--host-resolver-rules")
    return [a for a in args if a.split("=", 1)[0] not in drop]


def _guarded_fortress_class():
    """A Fortress launcher that always starts the engine behind the running
    _EgressGuard. Refuses to launch without one, so the browser can never come
    up with unchecked egress."""
    from tilion_fortress import Fortress

    if getattr(Fortress, "_egress_guarded", False):
        return Fortress

    class _GuardedFortress(Fortress):
        _egress_guarded = True

        def start(self):
            # A fresh port, so the driver can only attach to THIS (guarded) engine —
            # never to another browser already listening on the default 9222.
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", 0))
                self.port = s.getsockname()[1]
            return super().start()

        def _guard_args(self, host: str) -> None:
            if _guard is None or _guard.port == 0:
                raise RuntimeError("egress guard is not running; refusing to launch the browser")
            self.extra_args = _strip_proxy_flags(list(self.extra_args)) + _guard.browser_args(host)

        def _start_native(self, plat):
            self._guard_args("127.0.0.1")
            return super()._start_native(plat)

        def _start_docker(self):
            # The containerised engine reaches the host's loopback relay via Docker
            # Desktop's host alias.
            self._guard_args("host.docker.internal")
            return super()._start_docker()

    return _GuardedFortress


_PinnedResolver = None


def _pinned_resolver():
    """An aiohttp resolver that only ever returns addresses _resolve_public approved,
    so each connection is made to the address that was checked."""
    global _PinnedResolver
    if _PinnedResolver is None:
        import socket

        from aiohttp.abc import AbstractResolver

        class _Resolver(AbstractResolver):
            async def resolve(self, host, port=0, family=socket.AF_INET):
                return [{"hostname": host, "host": addr, "port": port, "family": fam,
                         "proto": 0, "flags": socket.AI_NUMERICHOST}
                        for fam, addr in await _resolve_public(host, port)]

            async def close(self) -> None:
                return None

        _PinnedResolver = _Resolver
    return _PinnedResolver()


class _GuardedHTTP:
    """Drop-in for the aiohttp session the facade's downloaders use (`.get()` as an
    async context manager). Redirects are followed here, one hop at a time. aiohttp
    hands hostnames to the pinned resolver but connects to IP literals without
    resolving, so each hop's scheme and literal address are checked before its
    request. Nothing is returned (or written by the caller) unless every hop was
    allowed."""

    _REDIRECTS = (301, 302, 303, 307, 308)
    _MAX_HOPS = 10

    def __init__(self, cookies_for=None) -> None:
        self._cookies_for = cookies_for

    @staticmethod
    def _check_hop(url) -> None:
        import ipaddress

        if url.scheme not in ("http", "https"):
            raise _EgressRefused(f"refused non-http(s) URL: {str(url)!r}")
        host = (url.host or "").strip("[]")
        if not host:
            raise _EgressRefused(f"invalid url: {str(url)!r}")
        try:
            ipaddress.ip_address(host.split("%", 1)[0])
        except ValueError:
            return
        if not _private_egress_allowed() and _ip_blocked(host):
            raise _EgressRefused(f"refused private/internal address {host!r} "
                                 "(set TILION_ALLOW_PRIVATE_EGRESS=1 to allow)")

    @asynccontextmanager
    async def get(self, url, *, headers=None, ssl=None, **_ignored):
        import aiohttp
        from yarl import URL

        connector = aiohttp.TCPConnector(resolver=_pinned_resolver(), use_dns_cache=False)
        timeout = aiohttp.ClientTimeout(total=60, connect=10)
        ssl_kw = {} if ssl is None else {"ssl": ssl}
        async with aiohttp.ClientSession(connector=connector, timeout=timeout,
                                         trust_env=False) as session:
            current = URL(str(url))
            for _hop in range(self._MAX_HOPS + 1):
                self._check_hop(current)
                hdrs = dict(headers or {})
                if self._cookies_for is not None:
                    cookie = await self._cookies_for(str(current))
                    if cookie:
                        hdrs["Cookie"] = cookie
                resp = await session.get(current, headers=hdrs, allow_redirects=False,
                                         **ssl_kw)
                location = resp.headers.get("Location")
                if resp.status in self._REDIRECTS and location:
                    resp.release()
                    current = current.join(URL(location))
                    continue
                try:
                    yield resp
                finally:
                    resp.release()
                return
            raise aiohttp.TooManyRedirects(None, (), message=f"too many redirects: {url}")


_nav_blocked: contextvars.ContextVar[set | None] = contextvars.ContextVar(
    "fortress_mcp_nav_blocked", default=None)


def _install_facade_guards() -> None:
    """Route the facade's in-process downloaders (Tab.download_url — used by
    download_file and the run_browser_task download flow — and the document
    fetcher behind extract_document) through _GuardedHTTP, and let crawl_site see
    which navigations the egress guard did not connect."""
    from tilion.core.tab import Tab
    from tilion.core.scraping import extractor as _extractor

    if not getattr(Tab.download_url, "_egress_guarded", False):
        async def download_url(self, url, output_path=None, headers=None,
                               use_browser_session=True):
            async def browser_cookies(hop: str) -> str:
                session = await self._ensure_session()
                got = await session.send("Network.getCookies", {"urls": [hop]})
                return "; ".join(f"{c['name']}={c['value']}"
                                 for c in (got or {}).get("cookies", []))

            http = _GuardedHTTP(browser_cookies if use_browser_session else None)
            return await self._do_download(http, url, output_path, dict(headers or {}))

        download_url._egress_guarded = True
        Tab.download_url = download_url

    if not getattr(Tab.goto, "_egress_guarded", False):
        _goto = Tab.goto

        @functools.wraps(_goto)
        async def goto(self, url, *args, **kwargs):
            try:
                return await _goto(self, url, *args, **kwargs)
            except Exception as exc:
                sink = _nav_blocked.get()
                if sink is not None and "ERR_SOCKS_" in str(exc):
                    sink.add(url)
                raise

        goto._egress_guarded = True
        Tab.goto = goto

    Extractor = _extractor.Extractor
    if not getattr(Extractor._download_url, "_egress_guarded", False):
        async def _download_url(self, url):
            async with _GuardedHTTP().get(url, ssl=True) as resp:
                if resp.status != 200:
                    raise _extractor.ExtractionError(f"HTTP {resp.status} fetching {url}")
                return await resp.read()

        _download_url._egress_guarded = True
        Extractor._download_url = _download_url


async def _ensure_egress_guard(upstream) -> None:
    """Start (or restart, if its loop is gone) the guard and make every Fortress
    launch in this process go through it."""
    global _guard
    import tilion_fortress

    loop = asyncio.get_running_loop()
    if _guard is not None and (_guard.loop is not loop or _guard._server is None):
        _guard = None
    if _guard is None:
        g = _EgressGuard(upstream)
        await g.start()
        _guard = g
    _guard._upstream = upstream
    tilion_fortress.Fortress = _guarded_fortress_class()
    _install_facade_guards()


def _write_root() -> str:
    """The directory tool-written files are confined to. Override with
    TILION_MCP_WRITE_DIR; defaults to <tempdir>/tilion-mcp."""
    import tempfile
    root = _env("MCP_WRITE_DIR") or os.path.join(tempfile.gettempdir(), "tilion-mcp")
    os.makedirs(root, exist_ok=True)
    return os.path.abspath(root)


def _confine_path(path: str | None, suffix: str) -> str:
    """Confine a tool-supplied write path to the sandbox root — blocks path
    traversal / overwriting arbitrary files (e.g. ~/.ssh/authorized_keys). Only the
    basename is used. Set TILION_MCP_ALLOW_ANY_PATH=1 to write anywhere (trusted
    local use). A None path yields a fresh temp name in the root."""
    import tempfile
    root = _write_root()
    if _env("MCP_ALLOW_ANY_PATH", "0") == "1" and path:
        return path
    if not path:
        fd, p = tempfile.mkstemp(suffix=suffix, prefix="tilion_", dir=root)
        os.close(fd)
        return p
    name = os.path.basename(path) or ("out" + suffix)
    if not os.path.splitext(name)[1]:
        name += suffix
    return os.path.join(root, name)


async def _log(ctx, msg: str) -> None:
    """Best-effort server→client log. Never breaks a tool if the client has no
    logging capability (or there's no active session, e.g. in tests)."""
    if ctx is not None:
        try:
            await ctx.info(msg)
        except Exception:
            pass


async def _check_params_urls(params: dict | None) -> None:
    """Defense-in-depth: SSRF-check any URL-looking values a flow might navigate to."""
    for v in (params or {}).values():
        if isinstance(v, str) and v[:8].lower().startswith(("http://", "https:/")):
            await _check_url(v)


@asynccontextmanager
async def _lifespan(_server):
    """Pre-warm the stealth browser at server startup so the agent's FIRST tool
    call is a ~150ms warm hit, not a ~2.2s cold launch. Disable with
    TILION_MCP_PREWARM=0. Shuts the browser down cleanly on exit."""
    if _env("MCP_PREWARM", "1") != "0":
        try:
            await _t()
        except Exception:
            pass  # never let a pre-warm failure block the server
    try:
        yield
    finally:
        global _tilion, _guard
        if _tilion is not None:
            try:
                await _tilion.close()
            except Exception:
                pass
            _tilion = None
        if _guard is not None:
            await _guard.close()
            _guard = None


mcp = FastMCP("Fortress Stealth Browser", lifespan=_lifespan)

# ── one shared browser for the whole server ─────────────────────────────────
# NOTE: an ASYNCIO lock, not a threading lock — holding a threading.Lock across an
# `await` deadlocks the event loop when two tool calls arrive concurrently. In
# 3.10+ asyncio.Lock() binds to the running loop lazily, so a module-level instance
# is safe.
_tilion: Tilion | None = None
_lock: asyncio.Lock | None = None


async def _t() -> Tilion:
    """Return the shared Tilion instance, starting it on first use and REBUILDING
    it if the browser has died (crash / dropped CDP). Concurrency-safe."""
    global _tilion, _lock
    if _lock is None:            # bind lazily to the running loop (atomic: no await)
        _lock = asyncio.Lock()
    async with _lock:
        stale_guard = _guard is None or _guard.loop is not asyncio.get_running_loop()
        if _tilion is not None and (stale_guard or not _tilion.is_healthy()):
            try:
                await _tilion.close()
            except Exception:
                pass
            _tilion = None
        if _tilion is None:
            base_url = _env("BASE_URL")
            api_key = _env("API_KEY")
            headless = (_env("MCP_HEADLESS", "1") != "0")
            # Egress + captcha come from env so an agent host can configure a residential
            # proxy and a captcha key without changing the tool surface. TILION_PROXY /
            # TILION_REGION / CAPTCHA_API_KEY are read by the facade itself; pass any
            # explicit ones through here too.
            inst = Tilion(
                headless=headless, base_url=base_url, api_key=api_key,
                proxy=_env("PROXY"),                 # TILION_PROXY
                region=_env("REGION"),               # TILION_REGION
                captcha_api_key=os.environ.get("CAPTCHA_API_KEY"),
                captcha_provider=os.environ.get("CAPTCHA_PROVIDER", "2captcha"),
            )
            await _ensure_egress_guard(getattr(inst, "_proxy", None))
            await inst.start()
            _tilion = inst
    return _tilion


# ── tools ───────────────────────────────────────────────────────────────────

def _cap(d: dict, limits: dict[str, int]) -> dict:
    """Trim oversized string fields so a tool response never floods the agent's
    context. Drops the raw-HTML dump by default (agents want text/markdown), and
    flags anything truncated."""
    out = dict(d)
    for field, n in limits.items():
        v = out.get(field)
        if isinstance(v, str) and len(v) > n:
            out[field] = v[:n]
            out[f"{field}_truncated"] = True
    return out


@mcp.tool(annotations=_READ)
@_safe
async def fetch_protected_page(url: str) -> dict:
    """Fetch a web page that normal HTTP clients / headless browsers CAN'T get —
    pages behind Cloudflare, DataDome, PerimeterX, Akamai, or that return 403 /
    'Access Denied' / 'Are you a robot' / CAPTCHA challenges.

    Use this the moment a requests/httpx/fetch call is blocked, rate-limited, or
    returns a bot-detection interstitial instead of the real content. It drives a
    real recompiled-Chromium stealth browser (Fortress) that passes bot checks,
    waits out the JS challenge, and returns the resolved HTML + text.

    Returns {url, status ('ok'|'blocked'), title, text, blocked}. (Raw HTML is
    dropped from the response to save context — use extract_page for structured
    content.)
    """
    await _check_url(url)
    t = await _t()
    r = await t.fetch(url)
    r.pop("html", None)                       # agents want text, not a raw-HTML dump
    return _cap(r, {"text": 20000})


@mcp.tool(annotations=_DESTRUCTIVE)
@_safe
async def run_browser_task(task: str, url: str, params: dict | None = None) -> dict:
    """Run a multi-step browser automation on a stealth browser that won't get
    flagged as a bot — logging in, paginating, infinite-scroll collection, table
    extraction, form fill, file download, multi-step checkout, SPA navigation.

    Use when a task needs real interaction (not just a fetch) on a site that
    detects/blocks automation. `task` is a flow name from `list_browser_tasks`;
    `params` carries flow arguments (selectors, credentials, etc).
    """
    valid = set(Tilion.list_tasks())
    if task not in valid:
        return {"status": "error",
                "error": f"unknown task {task!r}; call list_browser_tasks for valid names"}
    if url:
        await _check_url(url)
    await _check_params_urls(params)          # SSRF-check URL-bearing flow params too
    t = await _t()
    return await t.agent(task, url=url, **(params or {}))


@mcp.tool(annotations=_LOCAL)
@_safe
async def list_browser_tasks() -> list[str]:
    """List the browser-automation flow names accepted by run_browser_task
    (login, paginate_collect, infinite_scroll_collect, extract_table,
    multi_step_checkout, download_file, navigate_spa, ...)."""
    return Tilion.list_tasks()


@mcp.tool(annotations=_READ)
@_safe
async def search_web(query: str, count: int = 10) -> dict:
    """Run a web search through a real stealth browser (not a paid SERP API) and
    return organic results. Useful when you need fresh search results and SERP
    APIs are unavailable or the search engine blocks scripted queries.

    Returns {engine, query, results:[{title, url, snippet}...]}.
    """
    count = max(1, min(int(count), 50))
    t = await _t()
    return await t.search(query, count=count)


@mcp.tool(annotations=_READ)
@_safe
async def extract_page(url: str, schema: dict | None = None) -> dict:
    """Extract clean, LLM-ready content from a page that may be behind bot
    detection — returns markdown + tables + metadata (or a schema-shaped record if
    `schema` is given). Use instead of raw HTML scraping when you want structured,
    readable content and the site blocks normal scrapers.
    """
    await _check_url(url)
    t = await _t()
    r = await t.extract(url, schema=schema)
    r.pop("html", None)
    return _cap(r, {"markdown": 40000, "text": 20000})


def _drop_blocked_pages(r: dict, blocked: set[str]) -> dict:
    """The indexer lists a page before navigating to it; remove pages the egress
    guard never connected so they are not reported as crawled."""
    sitemap = r.get("sitemap")
    dropped = 0
    if isinstance(sitemap, str):
        kept = []
        for line in sitemap.split("\n"):
            s = line.strip()
            if s.startswith("<url><loc>") and s.endswith("</loc></url>") \
                    and s[len("<url><loc>"):-len("</loc></url>")] in blocked:
                dropped += 1
                continue
            kept.append(line)
        r["sitemap"] = "\n".join(kept)
    if dropped:
        for holder in (r, r.get("stats") if isinstance(r.get("stats"), dict) else {}):
            if isinstance(holder.get("pages_crawled"), int):
                holder["pages_crawled"] = max(0, holder["pages_crawled"] - dropped)
        r["pages_blocked"] = dropped
    return r


@mcp.tool(annotations=_READ)
@_safe
async def crawl_site(url: str, depth: int = 2, max_pages: int = 100,
                     ctx: Context | None = None) -> dict:
    """Crawl a whole website (BFS, auto-handles SPA/JS + lazy-load) through the
    stealth browser and return every discovered page/document + a sitemap. Use to
    map or harvest a site that blocks conventional crawlers.
    """
    await _check_url(url)
    depth = max(1, min(int(depth), 5))            # clamp: unbounded depth can run away
    max_pages = max(1, min(int(max_pages), 500))
    if ctx:
        await _log(ctx, f"crawling {url} (depth {depth}, up to {max_pages} pages)…")
    t = await _t()
    blocked: set[str] = set()
    token = _nav_blocked.set(blocked)
    try:
        r = await t.crawl(url, depth=depth, max_pages=max_pages)
    finally:
        _nav_blocked.reset(token)
    if blocked:
        r = _drop_blocked_pages(r, blocked)
    if ctx:
        await _log(ctx, f"crawled {r.get('pages_crawled', 0)} pages, {r.get('document_count', 0)} documents")
    docs = r.get("documents")                     # cap the doc list so a big crawl can't flood context
    if isinstance(docs, list) and len(docs) > 200:
        r["documents"] = docs[:200]
        r["documents_truncated"] = True
    return r


@mcp.tool(annotations=_READ)
@_safe
async def recon_site_apis(url: str, duration: float = 20.0,
                          ctx: Context | None = None) -> dict:
    """Reverse-engineer a site's PRIVATE API: drive the page in a stealth browser
    and capture the XHR/fetch endpoints, auth flow, and JSON traffic behind it
    (secret-scrubbed). Use when you want to hit a site's real backend API directly
    instead of scraping HTML.
    """
    await _check_url(url)
    duration = max(1.0, min(float(duration), 60.0))   # clamp: capture window bounded
    if ctx:
        await _log(ctx, f"capturing {url} network for {duration:.0f}s…")
    t = await _t()
    r = await t.recon(url, duration=duration)
    eps = r.get("api_endpoints")                       # cap endpoint list for context safety
    if isinstance(eps, list) and len(eps) > 100:
        r["api_endpoints"] = eps[:100]
        r["api_endpoints_truncated"] = True
    return r


@mcp.tool(annotations=_WRITE)
@_safe
async def screenshot_page(url: str, path: str | None = None) -> dict:
    """Screenshot a page (that may be behind bot detection) as PNG. Writes to
    `path` if given, else returns base64 (large images are saved to a temp file
    instead, to avoid flooding context). Use for visual verification/QA."""
    await _check_url(url)
    if path is not None:
        path = _confine_path(path, ".png")       # sandbox the write path
    t = await _t()
    r = await t.screenshot(url, path=path)
    b64 = r.get("png_base64")
    if b64 and len(b64) > 200_000:               # ~150KB image → too big to inline
        import base64
        tmp = _confine_path(None, ".png")
        with open(tmp, "wb") as fh:
            fh.write(base64.b64decode(b64))
        r.pop("png_base64", None)
        r["path"] = tmp
        r["note"] = "image too large to inline; saved to a file (pass path= to name it)"
    return r


@mcp.tool(annotations=_WRITE)
@_safe
async def save_page(url: str, path: str, format: str = "pdf") -> dict:
    """Save a page (behind bot detection or not) as pdf | html | text | screenshot
    to `path`. Use to archive/export a protected page as a PDF."""
    await _check_url(url)
    allowed = {"pdf", "html", "text", "screenshot", "png"}
    if format not in allowed:
        return {"status": "error", "error": f"format must be one of {sorted(allowed)}"}
    ext = {"text": ".txt", "screenshot": ".png"}.get(format, "." + format)
    path = _confine_path(path, ext)              # sandbox the write path
    t = await _t()
    return await t.save(url, path, format=format)


@mcp.tool(annotations=_READ)
@_safe
async def read_page(url: str) -> dict:
    """Get clean, reader-mode MARKDOWN of ANY web page (protected or not) — the
    readable article/content as markdown plus any tables. Use to read a page's
    content without the HTML noise. Returns {url, title, markdown, tables}.
    """
    await _check_url(url)
    t = await _t()
    r = await t.read(url)
    return _cap(r, {"markdown": 40000})


@mcp.tool(annotations=_READ)
@_safe
async def page_elements(url: str) -> dict:
    """Map a page's interactive STRUCTURE — its buttons, links, form fields, and
    headings (the layout/design overview). Use to discover what you can click or
    fill before calling click_button / fill_field. Returns
    {url, buttons[], links[], fields[], headings[]}.
    """
    await _check_url(url)
    t = await _t()
    return await t.elements(url)


@mcp.tool(annotations=_WRITE)
@_safe
async def click_button(text: str, url: str | None = None) -> dict:
    """Click a BUTTON or link by its visible text on the current page (navigates to
    `url` first if given). Use to press buttons, submit, open menus, follow links.
    Returns the resulting {clicked, url, title}.
    """
    if url:
        await _check_url(url)
    t = await _t()
    return await t.click(text, url=url)


@mcp.tool(annotations=_WRITE)
@_safe
async def fill_field(field: str, value: str, url: str | None = None,
                     submit: bool = False) -> dict:
    """Type `value` into a form FIELD (CSS selector, e.g. 'input[name=q]') on the
    current page (navigates to `url` first if given). Set submit=True to press Enter
    and submit — the reliable way to submit a search box. Pair with page_elements to
    find field selectors.
    """
    if url:
        await _check_url(url)
    t = await _t()
    return await t.fill(field, value, url=url, submit=submit)


@mcp.tool(annotations=_WRITE)
@_safe
async def press_key(key: str) -> dict:
    """Press a key on the current page: Enter (submit a focused field), Tab, Escape
    (dismiss a dialog), ArrowDown, PageDown, etc. Returns the resulting {url}.
    """
    t = await _t()
    return await t.press(key)


@mcp.tool(annotations=_READ)
@_safe
async def current_page() -> dict:
    """Get the current working page's URL and title WITHOUT navigating — use to
    check where you landed after click_button / fill_field(submit=True). Returns
    {open, url, title}.
    """
    t = await _t()
    return await t.current()


@mcp.tool(annotations=_READ)
@_safe
async def extract_document(source: str) -> dict:
    """Extract clean text/markdown + tables from a DOCUMENT — a PDF, DOCX, XLSX, CSV,
    or HTML file, given a local path OR a URL (even one behind bot detection). Use for
    reports, datasheets, filings, or any file the agent must read.
    """
    t = await _t()
    is_url = source[:4].lower() == "http"
    if is_url:
        await _check_url(source)
    r = await (t.extract_url(source) if is_url else t.extract_file(source))
    r.pop("html", None)
    return _cap(r, {"markdown": 40000, "text": 20000})


@mcp.tool(annotations=_READ)
@_safe
async def get_page_html(url: str) -> dict:
    """Get the RAW HTML of a page (behind bot detection or not). Use when you need the
    exact markup rather than cleaned markdown. Returns {url, html} (capped)."""
    await _check_url(url)
    t = await _t()
    return _cap(await t.get_html(url), {"html": 80000})


@mcp.tool(annotations=_READ)
@_safe
async def evaluate_js(expression: str, url: str | None = None) -> dict:
    """Run a JavaScript expression on the current (or a navigated) page and return its
    result. Use for custom scraping the high-level tools don't cover, e.g.
    `Array.from(document.querySelectorAll('.price')).map(e=>e.innerText)`.
    """
    if url:
        await _check_url(url)
    t = await _t()
    return await t.evaluate(expression, url=url)


@mcp.tool(annotations=_READ)
@_safe
async def wait_for(selector: str, url: str | None = None, timeout_ms: int = 10000) -> dict:
    """Wait for a CSS selector to appear (navigates to `url` first if given). Use
    before reading a page whose content loads late via JavaScript."""
    if url:
        await _check_url(url)
    timeout_ms = max(500, min(int(timeout_ms), 60000))
    t = await _t()
    return await t.wait_for(selector, url=url, timeout_ms=timeout_ms)


@mcp.tool(annotations=_WRITE)
@_safe
async def download_file(url: str, filename: str) -> dict:
    """Download a file (preserving the stealth browser's cookies/session) to a
    sandboxed path. Use for PDFs/CSVs/exports behind auth or bot detection.
    Returns {url, path, bytes}."""
    await _check_url(url)
    ext = os.path.splitext(filename)[1] or ".bin"
    dest = _confine_path(filename, ext)
    t = await _t()
    return await t.download(url, dest)


@mcp.tool(annotations=_READ)
@_safe
async def get_cookies(url: str | None = None) -> dict:
    """Get the cookies on the current (or a navigated) page — inspect or export an
    authenticated session. Returns {cookies:[...]}."""
    if url:
        await _check_url(url)
    t = await _t()
    return {"cookies": await t.get_cookies(url=url)}


@mcp.tool(annotations=_WRITE)
@_safe
async def save_profile(name: str = "session") -> dict:
    """Save the current authenticated session (cookies + localStorage) to a named
    profile so you can restore the login later with load_profile — no need to log in
    again. Do this AFTER a successful login (e.g. via run_browser_task)."""
    t = await _t()
    r = await t.save_profile(_confine_path(name, ".json"))
    r["profile"] = name
    return r


@mcp.tool(annotations=_WRITE)
@_safe
async def load_profile(name: str = "session") -> dict:
    """Restore a saved session (cookies + localStorage) from a named profile — reuse a
    login without re-authenticating. Navigate to the site afterward."""
    p = _confine_path(name, ".json")
    if not os.path.exists(p):
        return {"status": "error", "error": f"no profile {name!r} — call save_profile first"}
    t = await _t()
    r = await t.load_profile(p)
    r["profile"] = name
    return r


@mcp.tool(annotations=_READ)
@_safe
async def list_tabs() -> dict:
    """List the open browser tabs (index + url + which is current)."""
    t = await _t()
    return {"tabs": await t.list_tabs()}


@mcp.tool(annotations=_WRITE)
@_safe
async def close_tab(index: int) -> dict:
    """Close a tab by index (from list_tabs)."""
    t = await _t()
    return await t.close_tab(int(index))


@mcp.tool(annotations=_READ)
@_safe
async def detect_waf(url: str | None = None) -> dict:
    """Identify the anti-bot / WAF vendor protecting a page (Cloudflare, DataDome,
    PerimeterX, Akamai, Kasada, Incapsula) on the current page or a freshly-navigated `url`.

    Returns {vendor, challenged, confidence, strategy, signals}. Use it to decide the
    approach before hitting a hard target: `ip_and_wait`/Akamai and `behavior_*`/DataDome+
    PerimeterX want residential egress + human interaction; `wait_challenge`/Cloudflare and
    `pow_wait`/Kasada auto-clear or need time. `fetch_protected_page` already applies the
    right strategy automatically and returns the same `waf` info.
    """
    if url:
        await _check_url(url)
    t = await _t()
    return await t.detect_waf(url)


@mcp.tool(annotations=_WRITE)
@_safe
async def solve_captcha(url: str | None = None) -> dict:
    """Detect and solve a CAPTCHA on the current page (or a freshly-navigated `url`).

    Use when a page is gated by reCAPTCHA/hCaptcha/Turnstile. Requires a solver key in the
    server env (`CAPTCHA_API_KEY`, provider `CAPTCHA_PROVIDER` = 2captcha|anticaptcha|
    capsolver). Returns {detected, kind, solvable, solved}. `fetch_protected_page` already
    auto-solves when a key is set; use this for an explicit retry on an interactive page.
    """
    if url:
        await _check_url(url)
    t = await _t()
    return await t.solve_captcha(url)


@mcp.tool(annotations=_READ)
@_safe
async def get_egress_info() -> dict:
    """Report the current egress config: whether a proxy/region is set and the public IP
    the target actually sees. Use to confirm residential egress is active before hitting a
    hard target (a datacenter IP gets pre-classified as a bot regardless of fingerprint).
    Configure via env: TILION_PROXY=http://user:pass@host:port, TILION_REGION=us.
    """
    t = await _t()
    info = {"proxy_configured": t._proxy is not None,
            "proxy_type": getattr(t._proxy, "type", None),
            "region": t._region,
            "captcha_solver": bool(t._captcha_api_key)}
    try:
        r = await t.fetch("https://api.ipify.org?format=json", timeout_ms=20000)
        import json as _json
        info["public_ip"] = _json.loads(r.get("text", "{}") or "{}").get("ip")
    except Exception:
        info["public_ip"] = None
    return info


@mcp.tool(annotations=_READ)
@_safe
async def get_stealth_cdp_endpoint() -> dict:
    """Return a Chrome DevTools Protocol (CDP) websocket URL for a running stealth
    browser you can connect your OWN automation stack to — browser-use, Playwright,
    Puppeteer, Crawl4AI, Stagehand all accept a `cdp_url`.

    Use this when you already have browser-automation code but keep getting
    detected/blocked: point your existing `connect_over_cdp` / `cdp_url` at this
    endpoint to run the exact same code through the Fortress stealth engine.

    Returns {cdp_url}.
    """
    t = await _t()
    return {"cdp_url": t.cdp_url}


def main() -> None:
    """Console entry point (``tilion-mcp`` / ``python -m tilion.mcp``)."""
    # Windows consoles default to cp1252, so any non-latin1 glyph in a log line raises
    # UnicodeEncodeError and can kill the server. Force UTF-8 on the streams (JSON-RPC is
    # UTF-8 anyway) so no banner/log character can ever crash it. The banner itself is
    # kept ASCII as belt-and-suspenders.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except Exception:
            pass
    # Banner to STDERR only — stdout is the MCP stdio transport and must stay clean.
    print(
        "Tilion Fortress Stealth-Browser MCP  [Beta]\n"
        "  29 tools | local & free | hosted cloud (residential egress) coming soon\n"
        "  docs: DOCUMENTATION.md - more coming; benchmarks in the README\n"
        "  listening on stdio...",
        file=sys.stderr, flush=True,
    )
    mcp.run()


if __name__ == "__main__":
    main()
