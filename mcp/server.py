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
import base64
import contextlib
import functools
import ipaddress
import os
import secrets
import socket
import sys
from contextlib import asynccontextmanager
from urllib.parse import unquote, urlsplit

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
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    # normalise IPv4-mapped IPv6 (::ffff:169.254.169.254) to the v4 checks
    if getattr(ip, "ipv4_mapped", None) is not None:
        ip = ip.ipv4_mapped
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


async def _check_url(url: str) -> None:
    """SSRF guard for the local MCP: refuse localhost / private / cloud-metadata
    targets unless the operator opts in with TILION_ALLOW_PRIVATE_EGRESS=1.

    DNS resolution goes through the event loop's ASYNC resolver — a blocking
    socket.getaddrinfo here would stall every concurrent tool call and could not
    be cancelled by the per-tool timeout.

    This is an early, readable refusal only: a lookup here says nothing about the
    address used later. _EgressGuard and _pin_aiohttp bind each connection."""
    if _private_egress_allowed():
        return
    host = (urlsplit(url).hostname or "").strip("[]")
    if not host:
        raise ValueError(f"invalid url: {url!r}")
    if host.lower() in ("localhost", "metadata.google.internal"):
        raise ValueError(f"refused private/metadata host {host!r} "
                         "(set TILION_ALLOW_PRIVATE_EGRESS=1 to allow)")
    if _ip_blocked(host):                     # host is already a literal IP
        raise ValueError(f"refused private/internal address {host!r} "
                         "(set TILION_ALLOW_PRIVATE_EGRESS=1 to allow)")
    try:
        loop = asyncio.get_running_loop()
        infos = await loop.getaddrinfo(host, None)
    except Exception:
        return  # unresolvable → let the browser surface a clean nav error
    for info in infos:
        if _ip_blocked(info[4][0]):
            raise ValueError(f"refused private/internal address for {host!r} "
                             "(set TILION_ALLOW_PRIVATE_EGRESS=1 to allow)")


def _private_egress_allowed() -> bool:
    return _env("ALLOW_PRIVATE_EGRESS", "0") == "1"


def _addr_blocked(addr: str) -> bool:
    """_ip_blocked for a resolver ANSWER: anything that does not parse as an IP is
    refused rather than waved through."""
    try:
        ipaddress.ip_address(addr)
    except ValueError:
        return True
    return _ip_blocked(addr)


async def _pinned_addresses(host: str, port: int) -> list[str]:
    """Resolve ``host`` ONCE and return the addresses the caller must dial.

    Refuses when ANY answer is internal. The caller connects only to the returned
    list and never resolves the name again, so a rebinding answer arriving later
    (short TTL, a second lookup by another component) is never used."""
    host = (host or "").strip("[]")
    if not host:
        raise ValueError("missing host")
    allow = _private_egress_allowed()
    if not allow and host.lower().rstrip(".") in ("localhost", "metadata.google.internal"):
        raise PermissionError(f"refused private/metadata host {host!r}")
    try:
        ipaddress.ip_address(host)
        addrs = [host]
    except ValueError:
        infos = await asyncio.get_running_loop().getaddrinfo(
            host, port, type=socket.SOCK_STREAM)
        addrs = list(dict.fromkeys(info[4][0] for info in infos))
    if not addrs:
        raise OSError(f"{host!r} did not resolve")
    if not allow:
        blocked = [a for a in addrs if _addr_blocked(a)]
        if blocked:
            raise PermissionError(f"refused {host!r}: resolves to private/internal "
                                  f"address {blocked[0]}")
    return addrs


def _authority(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


_HOP_HEADERS = frozenset({"connection", "keep-alive", "proxy-connection",
                          "proxy-authorization", "proxy-authenticate", "te",
                          "trailer", "upgrade"})


class _EgressGuard:
    """Loopback HTTP(S) forward proxy that every browser connection goes through.

    With ``--proxy-server`` set, Chromium hands the hostname to the proxy and does
    not resolve it itself. The guard resolves each CONNECT / absolute-form request
    once (_pinned_addresses), refuses internal answers, and dials exactly the
    address it checked: TLS stays end-to-end between the browser and the site.
    The operator's TILION_PROXY, if any, is chained behind it and is sent the
    pinned IP rather than the name, so it cannot re-resolve the name either."""

    _CANARY_PATH = "/__fortress-egress-check__/"

    def __init__(self) -> None:
        self._server: asyncio.base_events.Server | None = None
        self.port = 0
        self.upstream: str | None = None
        self._up: tuple[str, int, str | None] | None = None
        self._canaries: dict[str, asyncio.Event] = {}
        self._verified: object | None = None
        # Loopback endpoints the MCP process itself must reach over aiohttp (the
        # browser's CDP socket, this guard, the operator's upstream proxy).
        self.exempt: set[tuple[str, int]] = set()

    @property
    def running(self) -> bool:
        return self._server is not None and self._server.is_serving()

    @property
    def proxy_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def set_upstream(self, proxy: str | None) -> None:
        self.upstream, self._up = proxy or None, None
        if not proxy:
            return
        u = urlsplit(proxy if "://" in proxy else f"http://{proxy}")
        if not u.hostname or not u.port:
            raise ValueError("invalid TILION_PROXY; use http://[user:pass@]host:port")
        auth = None
        if u.username is not None:
            cred = f"{unquote(u.username)}:{unquote(u.password or '')}".encode()
            auth = "Proxy-Authorization: Basic " + base64.b64encode(cred).decode()
        self._up = (u.hostname, u.port, auth)
        self.exempt.add((u.hostname, u.port))

    def exempt_url(self, url: str | None) -> None:
        u = urlsplit(url or "")
        if u.hostname and u.port:
            self.exempt.add((u.hostname, u.port))

    async def start(self) -> None:
        if self.running:
            return
        self._server = await asyncio.start_server(self._serve, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        self.exempt.add(("127.0.0.1", self.port))

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await self._server.wait_closed()
            self._server = None
        self._verified = None

    async def verify(self, t) -> None:
        """Prove ``t`` really sends its traffic through this guard before any tool
        navigates it, and remember that for this exact instance only.

        The canary is a loopback URL the guard answers itself. It only arrives as a
        proxied request when the browser honours --proxy-server AND does not
        bypass the proxy for loopback, which is what pinning depends on. A
        rebuilt browser is a different object and is checked again."""
        if t is self._verified and self.running:
            return
        if not self.running:
            raise PermissionError("egress guard is not running; refusing to navigate")
        token = secrets.token_hex(16)
        seen = self._canaries[token] = asyncio.Event()
        page = None
        try:
            page = await asyncio.wait_for(
                t.page(f"http://127.0.0.1:{self.port}{self._CANARY_PATH}{token}"), 30)
            await asyncio.wait_for(seen.wait(), 10)
        except Exception:
            pass
        finally:
            self._canaries.pop(token, None)
            if page is not None:
                with contextlib.suppress(Exception):
                    await page.close()
        if not seen.is_set():
            raise PermissionError(
                "browser egress is not routed through the MCP egress guard, so the "
                "address it connects to cannot be pinned; refusing to navigate "
                "(set TILION_ALLOW_PRIVATE_EGRESS=1 to run without the guard)")
        self._verified = t

    async def _serve(self, reader: asyncio.StreamReader,
                     writer: asyncio.StreamWriter) -> None:
        up_writer = None
        try:
            try:
                head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
            except (asyncio.IncompleteReadError, asyncio.LimitOverrunError,
                    asyncio.TimeoutError, ConnectionError):
                return
            lines = head[:-4].decode("latin-1").split("\r\n")
            parts = lines[0].split(" ")
            if len(parts) != 3:
                return await self._reply(writer, 400, "Bad Request")
            method, target, version = parts
            headers = [h for h in lines[1:] if h]
            tunnel = method.upper() == "CONNECT"
            try:
                u = urlsplit(("//" + target) if tunnel else target)
                port = u.port or (443 if tunnel else 80)
            except ValueError:
                return await self._reply(writer, 400, "Bad Request")
            if not u.hostname or (not tunnel and u.scheme.lower() != "http"):
                return await self._reply(writer, 400, "Bad Request")
            if (not tunnel and u.hostname == "127.0.0.1" and port == self.port
                    and u.path.startswith(self._CANARY_PATH)):
                ev = self._canaries.get(u.path[len(self._CANARY_PATH):])
                if ev is not None:
                    ev.set()
                return await self._reply(writer, 200, "OK", b"fortress egress guard")
            try:
                addrs = await _pinned_addresses(u.hostname, port)
            except PermissionError as exc:
                return await self._reply(writer, 403, "Forbidden",
                                         f"refused by Fortress MCP egress guard: {exc}".encode())
            except Exception:
                return await self._reply(writer, 502, "Bad Gateway")
            try:
                up_reader, up_writer = await self._dial(addrs, port, tunnel)
            except Exception:
                return await self._reply(writer, 502, "Bad Gateway")
            if tunnel:
                writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                path = (u.path or "/") + (f"?{u.query}" if u.query else "")
                if self._up is not None:
                    path = f"http://{_authority(addrs[0], port)}{path}"
                out = [f"{method} {path} {version}"]
                out += [h for h in headers
                        if h.split(":", 1)[0].strip().lower() not in _HOP_HEADERS]
                if not any(h.lower().startswith("host:") for h in headers):
                    out.append(f"Host: {u.netloc.rsplit('@', 1)[-1]}")
                if self._up is not None and self._up[2]:
                    out.append(self._up[2])
                out.append("Connection: close")
                up_writer.write(("\r\n".join(out) + "\r\n\r\n").encode("latin-1"))
            await asyncio.gather(self._pipe(reader, up_writer),
                                 self._pipe(up_reader, writer))
        except Exception:
            pass
        finally:
            for w in (up_writer, writer):
                if w is not None:
                    with contextlib.suppress(Exception):
                        w.close()

    async def _dial(self, addrs: list[str], port: int, tunnel: bool):
        if self._up is None:
            last: Exception = OSError("no address")
            for addr in addrs:
                try:
                    return await asyncio.wait_for(asyncio.open_connection(addr, port), 15)
                except Exception as exc:  # noqa: BLE001 - try the next pinned address
                    last = exc
            raise last
        host, up_port, auth = self._up
        r, w = await asyncio.wait_for(asyncio.open_connection(host, up_port), 15)
        if tunnel:
            dest = _authority(addrs[0], port)
            req = f"CONNECT {dest} HTTP/1.1\r\nHost: {dest}\r\n"
            if auth:
                req += auth + "\r\n"
            w.write((req + "\r\n").encode("latin-1"))
            resp = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), 30)
            status = resp.split(b" ", 2)
            if len(status) < 2 or status[1] != b"200":
                w.close()
                raise OSError("upstream proxy refused CONNECT")
        return r, w

    @staticmethod
    async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
        try:
            while True:
                data = await src.read(65536)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
        except Exception:
            pass
        finally:
            with contextlib.suppress(Exception):
                dst.close()

    @staticmethod
    async def _reply(writer: asyncio.StreamWriter, code: int, reason: str,
                     body: bytes = b"") -> None:
        writer.write(f"HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\n"
                     f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
                     .encode() + body)
        with contextlib.suppress(Exception):
            await writer.drain()


_egress: _EgressGuard | None = None


def _pin_aiohttp(guard: _EgressGuard) -> None:
    """Apply the same rule to the facade's direct aiohttp fetches (download_file,
    document extraction, sitemap discovery), which never touch the browser.

    aiohttp connects only to the list TCPConnector._resolve_host returns, so the
    check runs on exactly the addresses that will be dialled, including literal IPs
    reached through a redirect."""
    try:
        from aiohttp.connector import TCPConnector
    except ImportError:
        return
    orig = getattr(TCPConnector, "_resolve_host", None)
    if orig is None:
        raise RuntimeError("unsupported aiohttp: cannot pin its connections; "
                           "set TILION_ALLOW_PRIVATE_EGRESS=1 to run unguarded")
    if getattr(orig, "_fortress_pinned", False):
        return

    async def _resolve_host(self, host, port, traces=None):
        res = await orig(self, host, port, traces=traces)
        if _private_egress_allowed():
            return res
        for r in res:
            if ((r.get("hostname"), port) in guard.exempt
                    or (r.get("host"), port) in guard.exempt):
                continue
            if _addr_blocked(r.get("host") or ""):
                raise PermissionError(f"refused {host!r}: resolves to private/internal "
                                      f"address {r.get('host')}")
        return res

    _resolve_host._fortress_pinned = True
    TCPConnector._resolve_host = _resolve_host


async def _start_behind_guard(inst: Tilion, guard: _EgressGuard) -> None:
    """Start ``inst`` with Fortress launched so the guard sees every request.

    Chromium skips the proxy for loopback and link-local literals unless
    ``<-loopback>`` is in the bypass list, so a redirect to 127.0.0.1 or
    169.254.169.254 would otherwise go direct."""
    import tilion_fortress

    base = tilion_fortress.Fortress

    class _PinnedFortress(base):
        def __init__(self, *args, extra_args=None, **kwargs):
            super().__init__(*args, extra_args=[*(extra_args or []),
                                                "--proxy-bypass-list=<-loopback>"], **kwargs)

        def _start_docker(self):
            # Inside the container 127.0.0.1 is the container itself.
            self.extra_args = [
                a.replace("--proxy-server=127.0.0.1:", "--proxy-server=host.docker.internal:", 1)
                for a in self.extra_args]
            return super()._start_docker()

        def start(self):
            super().start()
            guard.exempt_url(self.cdp_url)
            return self

    tilion_fortress.Fortress = _PinnedFortress
    try:
        await inst.start()
    finally:
        tilion_fortress.Fortress = base


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
            await _browser()
        except Exception:
            pass  # never let a pre-warm failure block the server
    try:
        yield
    finally:
        global _tilion
        if _tilion is not None:
            try:
                await _tilion.close()
            except Exception:
                pass
            _tilion = None
        if _egress is not None:
            await _egress.close()


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
    global _tilion, _lock, _egress
    if _lock is None:            # bind lazily to the running loop (atomic: no await)
        _lock = asyncio.Lock()
    async with _lock:
        if _tilion is not None and not _tilion.is_healthy():
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
            proxy = _env("PROXY")                    # TILION_PROXY
            guarded = not _private_egress_allowed()
            if guarded:
                # The browser talks only to the egress guard; TILION_PROXY is chained
                # behind it.
                if _egress is None:
                    _egress = _EgressGuard()
                await _egress.start()
                _egress.set_upstream(proxy)
                _pin_aiohttp(_egress)
                proxy = _egress.proxy_url
            inst = Tilion(
                headless=headless, base_url=base_url, api_key=api_key,
                proxy=proxy,
                region=_env("REGION"),               # TILION_REGION
                captcha_api_key=os.environ.get("CAPTCHA_API_KEY"),
                captcha_provider=os.environ.get("CAPTCHA_PROVIDER", "2captcha"),
            )
            if guarded:
                await _start_behind_guard(inst, _egress)
            else:
                await inst.start()
            _tilion = inst
    return _tilion


async def _browser() -> Tilion:
    """The shared browser, for tools. Unless private egress is explicitly allowed,
    it is only handed out once it has proven its traffic goes through the egress
    guard (see _EgressGuard.verify); otherwise the tool fails closed."""
    t = await _t()
    if not _private_egress_allowed():
        if _egress is None:
            raise PermissionError("egress guard is not running; refusing to navigate")
        await _egress.verify(t)
    return t


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
    t = await _browser()
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
    t = await _browser()
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
    t = await _browser()
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
    t = await _browser()
    r = await t.extract(url, schema=schema)
    r.pop("html", None)
    return _cap(r, {"markdown": 40000, "text": 20000})


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
    t = await _browser()
    r = await t.crawl(url, depth=depth, max_pages=max_pages)
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
    t = await _browser()
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
    t = await _browser()
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
    t = await _browser()
    return await t.save(url, path, format=format)


@mcp.tool(annotations=_READ)
@_safe
async def read_page(url: str) -> dict:
    """Get clean, reader-mode MARKDOWN of ANY web page (protected or not) — the
    readable article/content as markdown plus any tables. Use to read a page's
    content without the HTML noise. Returns {url, title, markdown, tables}.
    """
    await _check_url(url)
    t = await _browser()
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
    t = await _browser()
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
    t = await _browser()
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
    t = await _browser()
    return await t.fill(field, value, url=url, submit=submit)


@mcp.tool(annotations=_WRITE)
@_safe
async def press_key(key: str) -> dict:
    """Press a key on the current page: Enter (submit a focused field), Tab, Escape
    (dismiss a dialog), ArrowDown, PageDown, etc. Returns the resulting {url}.
    """
    t = await _browser()
    return await t.press(key)


@mcp.tool(annotations=_READ)
@_safe
async def current_page() -> dict:
    """Get the current working page's URL and title WITHOUT navigating — use to
    check where you landed after click_button / fill_field(submit=True). Returns
    {open, url, title}.
    """
    t = await _browser()
    return await t.current()


@mcp.tool(annotations=_READ)
@_safe
async def extract_document(source: str) -> dict:
    """Extract clean text/markdown + tables from a DOCUMENT — a PDF, DOCX, XLSX, CSV,
    or HTML file, given a local path OR a URL (even one behind bot detection). Use for
    reports, datasheets, filings, or any file the agent must read.
    """
    t = await _browser()
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
    t = await _browser()
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
    t = await _browser()
    return await t.evaluate(expression, url=url)


@mcp.tool(annotations=_READ)
@_safe
async def wait_for(selector: str, url: str | None = None, timeout_ms: int = 10000) -> dict:
    """Wait for a CSS selector to appear (navigates to `url` first if given). Use
    before reading a page whose content loads late via JavaScript."""
    if url:
        await _check_url(url)
    timeout_ms = max(500, min(int(timeout_ms), 60000))
    t = await _browser()
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
    t = await _browser()
    return await t.download(url, dest)


@mcp.tool(annotations=_READ)
@_safe
async def get_cookies(url: str | None = None) -> dict:
    """Get the cookies on the current (or a navigated) page — inspect or export an
    authenticated session. Returns {cookies:[...]}."""
    if url:
        await _check_url(url)
    t = await _browser()
    return {"cookies": await t.get_cookies(url=url)}


@mcp.tool(annotations=_WRITE)
@_safe
async def save_profile(name: str = "session") -> dict:
    """Save the current authenticated session (cookies + localStorage) to a named
    profile so you can restore the login later with load_profile — no need to log in
    again. Do this AFTER a successful login (e.g. via run_browser_task)."""
    t = await _browser()
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
    t = await _browser()
    r = await t.load_profile(p)
    r["profile"] = name
    return r


@mcp.tool(annotations=_READ)
@_safe
async def list_tabs() -> dict:
    """List the open browser tabs (index + url + which is current)."""
    t = await _browser()
    return {"tabs": await t.list_tabs()}


@mcp.tool(annotations=_WRITE)
@_safe
async def close_tab(index: int) -> dict:
    """Close a tab by index (from list_tabs)."""
    t = await _browser()
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
    t = await _browser()
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
    t = await _browser()
    return await t.solve_captcha(url)


@mcp.tool(annotations=_READ)
@_safe
async def get_egress_info() -> dict:
    """Report the current egress config: whether a proxy/region is set and the public IP
    the target actually sees. Use to confirm residential egress is active before hitting a
    hard target (a datacenter IP gets pre-classified as a bot regardless of fingerprint).
    Configure via env: TILION_PROXY=http://user:pass@host:port, TILION_REGION=us.
    """
    t = await _browser()
    proxy = t._proxy
    if _egress is not None and t is _egress._verified:
        # t._proxy is the local egress guard; report what it chains to.
        from tilion.facade import _parse_proxy
        proxy = _parse_proxy(_egress.upstream)
    info = {"proxy_configured": proxy is not None,
            "proxy_type": getattr(proxy, "type", None),
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
    t = await _browser()
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
