"""Cache-hit launches must not execute an unverified browser launcher.

The installer returns a cached launcher as soon as the file exists, before it
fetches SHA256SUMS and before it compares a digest. ``Fortress.start`` and the
``tilion-fortress`` CLI then pass that path to the process spawner.

These tests are the spec for a fix. They fail while that short-circuit is
present. A fix has to refuse a launcher whose bytes are not the published
bundle, must not run or modify that file before refusing, and must not spawn a
path inside the cache after a successful check: an attacker who can write the
cache can replace the file between the check and the exec. Docker fallback does
not use this launcher and is not covered here.

Run:  python3 -m pytest sdk/python/tests/test_cache_short_circuit.py -q
"""
from __future__ import annotations

import hashlib
import io
import os
import signal
import socket
import subprocess
import sys
import tarfile
import textwrap
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tilion_fortress as tf  # noqa: E402

SDK_PYTHON = Path(__file__).resolve().parents[1]


def _cdp_script(marker: Path) -> str:
    marker_lit = repr(str(marker))
    return textwrap.dedent(
        f"""\
        #!/usr/bin/env python3
        import sys
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        with open({marker_lit}, "w") as fh:
            fh.write("executed")
        port = 9
        for arg in sys.argv[1:]:
            if arg.startswith("--remote-debugging-port="):
                port = int(arg.split("=", 1)[1])

        class H(BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'{{"webSocketDebuggerUrl":"ws://127.0.0.1/planted"}}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                return

        ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
        """
    )


def _marker_script(marker: Path, text: str) -> str:
    return (
        "#!/usr/bin/env python3\n"
        f"with open({str(marker)!r}, 'w') as fh:\n"
        f"    fh.write({text!r})\n"
    )


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _wait_until(predicate, seconds: float) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


class ReleaseServer:
    """Local stand-in for the release host named by FORTRESS_DOWNLOAD_HOST."""

    def __init__(self):
        self.gets: dict[str, bytes] = {}
        self.head_ok: set[str] = set()
        self.hits: list[tuple[str, str]] = []
        self.httpd = None
        self.host = ""

    def __enter__(self):
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self._send(False)

            def do_HEAD(self):
                self._send(True)

            def _send(self, head: bool):
                name = self.path.split("?", 1)[0].lstrip("/")
                owner.hits.append((self.command, name))
                if head:
                    if name not in owner.head_ok and name not in owner.gets:
                        self.send_response(404)
                        self.end_headers()
                        return
                    body = owner.gets.get(name, b"")
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    return
                body = owner.gets.get(name)
                if body is None:
                    self.send_response(404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                return

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.httpd.daemon_threads = True
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.host = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()

    def publish_mismatch(self, asset: str):
        digest = hashlib.sha256(b"unrelated-archive").hexdigest()
        self.gets["SHA256SUMS"] = f"{digest}  {asset}\n".encode()
        self.head_ok.add(asset)

    def publish_archive(self, asset: str, archive: bytes):
        digest = hashlib.sha256(archive).hexdigest()
        self.gets["SHA256SUMS"] = f"{digest}  {asset}\n".encode()
        self.gets[asset] = archive
        self.head_ok.add(asset)


def _archive(plat: str, script: str) -> bytes:
    _asset, kind, rel = tf._ASSETS[plat]
    data = script.encode()
    buf = io.BytesIO()
    if kind == "tar":
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            info = tarfile.TarInfo(name=rel)
            info.size = len(data)
            info.mode = 0o755
            info.mtime = 0
            tar.addfile(info, io.BytesIO(data))
    else:
        with zipfile.ZipFile(buf, "w") as zf:
            info = zipfile.ZipInfo(rel)
            info.external_attr = 0o755 << 16
            zf.writestr(info, data)
    return buf.getvalue()


def _plant(cache: Path, tag: str, plat: str, body: str) -> Path:
    rel = tf._ASSETS[plat][2]
    path = cache / tag / plat / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or path.exists():
        path.unlink()
    path.write_text(body)
    path.chmod(0o755)
    return path


def _executed_paths(argv: list[str]) -> list[str]:
    if (
        len(argv) >= 3
        and Path(argv[0]).name.lower() in {"cmd", "cmd.exe"}
        and argv[1].lower() == "/c"
    ):
        return [argv[2]]
    return [argv[0]] if argv else []


def _under(root: Path, candidate: str) -> bool:
    try:
        Path(candidate).resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return False
    return True


@pytest.fixture
def browser_cache(monkeypatch, tmp_path):
    cache = tmp_path / "browsers"
    cache.mkdir()
    monkeypatch.setattr(tf, "_CACHE", cache)
    return cache


def _refuse_public_start(cache: Path, channel: str, plat: str, monkeypatch, system: str, machine: str):
    """Plant a launcher and require start() to refuse it without running it."""
    tag = tf._CHANNELS[channel]["tag"]
    asset = tf._ASSETS[plat][0]
    marker = cache.parent / f"executed-{plat}-{channel}"
    marker.unlink(missing_ok=True)
    launcher = _plant(cache, tag, plat, _cdp_script(marker))
    before = launcher.read_bytes()
    port = _free_port()
    with ReleaseServer() as srv:
        srv.publish_mismatch(asset)
        monkeypatch.setenv("FORTRESS_DOWNLOAD_HOST", srv.host)
        if system is not None:
            monkeypatch.setattr(tf.platform, "system", lambda: system)
            monkeypatch.setattr(tf.platform, "machine", lambda: machine)
        f = tf.Fortress(port=port, channel=channel, headless=True)
        exc = None
        try:
            try:
                f.start()
            except Exception as err:  # noqa: BLE001 - the fix chooses the exception type
                exc = err
            _wait_until(marker.exists, 0.4)
            if marker.exists() or exc is None:
                pytest.fail(
                    "planted launcher was executed without a matching published digest; "
                    f"download-host hits={srv.hits!r} marker={marker.exists()} exc={exc!r}"
                )
            if "Docker" in str(exc):
                pytest.fail(f"start() left the native launcher path: {exc}")
            assert launcher.read_bytes() == before
            assert launcher.is_file()
        finally:
            f.close()


@pytest.mark.parametrize("channel", ["stable", "latest"])
def test_start_refuses_preseeded_linux_launcher(browser_cache, monkeypatch, channel):
    # start() only takes the native cache path for the resolved host platform.
    if tf.resolve_platform() != "linux-x64":
        pytest.fail(f"linux cache path is not the one start() uses here: {tf.resolve_platform()}")
    _refuse_public_start(browser_cache, channel, "linux-x64", monkeypatch, None, None)


@pytest.mark.parametrize(
    "plat,machine",
    [("mac-arm64", "arm64"), ("mac-x64", "x86_64")],
)
def test_start_refuses_preseeded_mac_launcher(browser_cache, monkeypatch, plat, machine):
    _refuse_public_start(
        browser_cache, "stable", plat, monkeypatch, "Darwin", machine
    )


def test_start_does_not_spawn_preseeded_windows_launcher(browser_cache, monkeypatch):
    plat, channel = "win-x64", "stable"
    tag = tf._CHANNELS[channel]["tag"]
    asset = tf._ASSETS[plat][0]
    marker = browser_cache.parent / "executed-win"
    launcher = _plant(browser_cache, tag, plat, _cdp_script(marker))
    before = launcher.read_bytes()
    spawned: list[list[str]] = []

    def popen(args, *a, **kw):
        spawned.append([str(x) for x in args])
        raise RuntimeError("intercepted spawn")

    monkeypatch.setattr(tf.subprocess, "Popen", popen)
    monkeypatch.setattr(tf.platform, "system", lambda: "Windows")
    monkeypatch.setattr(tf.platform, "machine", lambda: "amd64")
    with ReleaseServer() as srv:
        srv.publish_mismatch(asset)
        monkeypatch.setenv("FORTRESS_DOWNLOAD_HOST", srv.host)
        f = tf.Fortress(port=_free_port(), channel=channel, headless=True)
        exc = None
        try:
            f.start()
        except Exception as err:  # noqa: BLE001
            exc = err
        finally:
            f.close()
        ran = [argv for argv in spawned if str(launcher) in argv]
        if ran or marker.exists():
            pytest.fail(
                "planted Windows launcher was passed to the process spawner; "
                f"argv={spawned!r} hits={srv.hits!r}"
            )
        assert exc is not None
        assert "Docker" not in str(exc)
        assert "intercepted spawn" not in str(exc)
        assert launcher.read_bytes() == before


def test_symlink_launcher_is_not_followed(browser_cache, monkeypatch):
    plat, channel = "linux-x64", "stable"
    tag = tf._CHANNELS[channel]["tag"]
    asset = tf._ASSETS[plat][0]
    marker = browser_cache.parent / "executed-symlink"
    target = browser_cache.parent / "outside-payload"
    target.write_text(_cdp_script(marker))
    target.chmod(0o755)
    rel = tf._ASSETS[plat][2]
    link = browser_cache / tag / plat / rel
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(target)
    with ReleaseServer() as srv:
        srv.publish_mismatch(asset)
        monkeypatch.setenv("FORTRESS_DOWNLOAD_HOST", srv.host)
        f = tf.Fortress(port=_free_port(), channel=channel, headless=True)
        exc = None
        try:
            try:
                f.start()
            except Exception as err:  # noqa: BLE001
                exc = err
            _wait_until(marker.exists, 0.4)
            if marker.exists() or exc is None:
                pytest.fail(
                    "symlink launcher was executed; "
                    f"hits={srv.hits!r} exc={exc!r}"
                )
            assert "Docker" not in str(exc)
            assert link.is_symlink()
            assert os.readlink(link) == str(target)
            assert target.read_bytes() == _cdp_script(marker).encode()
        finally:
            f.close()


def test_replaced_launcher_after_verified_download_is_not_executed(browser_cache, monkeypatch):
    plat, channel = "linux-x64", "stable"
    tag = tf._CHANNELS[channel]["tag"]
    asset = tf._ASSETS[plat][0]
    verified = browser_cache.parent / "verified-marker"
    planted = browser_cache.parent / "planted-marker"
    good = _marker_script(verified, "verified")
    evil = _marker_script(planted, "planted")
    archive = _archive(plat, good)
    with ReleaseServer() as srv:
        srv.publish_archive(asset, archive)
        monkeypatch.setenv("FORTRESS_DOWNLOAD_HOST", srv.host)
        launcher = tf._download(plat, srv.host, tag)
        assert verified.exists() is False
        launcher.write_text(evil)
        launcher.chmod(0o755)
        tampered = launcher.read_bytes()
        f = tf.Fortress(channel=channel, headless=True)
        exc = None
        try:
            try:
                f._start_native(plat)
            except Exception as err:  # noqa: BLE001
                exc = err
            _wait_until(lambda: planted.exists() or verified.exists(), 0.6)
            # _start_native assigns _proc only after it has decided to spawn.
            spawned = f._proc is not None
            if planted.exists() or verified.exists() or spawned or exc is None:
                pytest.fail(
                    "a launcher replaced after a verified download was started; "
                    f"planted={planted.exists()} verified={verified.exists()} "
                    f"spawned={spawned} exc={exc!r}"
                )
            assert launcher.read_bytes() == tampered
        finally:
            f.close()


def test_verified_launcher_is_not_reread_from_the_cache(browser_cache, monkeypatch):
    """A check that hashes the cache path and then spawns that same path still loses.

    The wrapper stands in for an attacker writing the cache in the interval after
    the bytes were read and before the spawn system call. Spawn arguments are the
    ones ``_start_native`` builds; only the executable path is rewritten, and only
    when it still points inside the cache.
    """
    plat, channel = "linux-x64", "stable"
    tag = tf._CHANNELS[channel]["tag"]
    asset = tf._ASSETS[plat][0]
    verified = browser_cache.parent / "verified-race"
    planted = browser_cache.parent / "planted-race"
    good = _marker_script(verified, "verified")
    evil = _marker_script(planted, "planted")
    archive = _archive(plat, good)
    cache_execs: list[str] = []
    real_popen = subprocess.Popen

    def racing(args, *a, **kw):
        argv = [str(x) for x in (args if isinstance(args, (list, tuple)) else [args])]
        for exe in _executed_paths(argv):
            path = Path(exe)
            if path.is_file() and _under(browser_cache, exe):
                cache_execs.append(exe)
                path.write_text(evil)
                path.chmod(0o755)
        return real_popen(args, *a, **kw)

    monkeypatch.setattr(tf.subprocess, "Popen", racing)
    with ReleaseServer() as srv:
        srv.publish_archive(asset, archive)
        monkeypatch.setenv("FORTRESS_DOWNLOAD_HOST", srv.host)
        launcher = _plant(browser_cache, tag, plat, good)
        (browser_cache / tag / plat / asset).write_bytes(archive)
        f = tf.Fortress(channel=channel, headless=True)
        exc = None
        try:
            f._start_native(plat)
        except Exception as err:  # noqa: BLE001
            exc = err
        finally:
            _wait_until(lambda: planted.exists() or verified.exists(), 1.0)
            if f._proc is not None:
                f.close()
        if cache_execs or planted.exists() or not verified.exists():
            pytest.fail(
                "cached launcher path was reusable after verification; "
                f"cache_execs={cache_execs!r} planted={planted.exists()} "
                f"verified={verified.exists()} exc={exc!r} launcher_now={launcher.read_text()!r}"
            )


def test_windows_launcher_is_not_reread_from_the_cache(browser_cache, monkeypatch):
    plat, channel = "win-x64", "stable"
    tag = tf._CHANNELS[channel]["tag"]
    asset = tf._ASSETS[plat][0]
    verified = browser_cache.parent / "verified-win-race"
    planted = browser_cache.parent / "planted-win-race"
    good = _marker_script(verified, "verified")
    evil = _marker_script(planted, "planted")
    archive = _archive(plat, good)
    cache_execs: list[str] = []
    real_popen = subprocess.Popen

    def racing(args, *a, **kw):
        argv = [str(x) for x in (args if isinstance(args, (list, tuple)) else [args])]
        for exe in _executed_paths(argv):
            path = Path(exe)
            if path.is_file() and _under(browser_cache, exe):
                cache_execs.append(exe)
                path.write_text(evil)
                path.chmod(0o755)
        return real_popen(args, *a, **kw)

    monkeypatch.setattr(tf.subprocess, "Popen", racing)
    monkeypatch.setattr(tf.platform, "system", lambda: "Windows")
    monkeypatch.setattr(tf.platform, "machine", lambda: "amd64")
    with ReleaseServer() as srv:
        srv.publish_archive(asset, archive)
        monkeypatch.setenv("FORTRESS_DOWNLOAD_HOST", srv.host)
        _plant(browser_cache, tag, plat, good)
        (browser_cache / tag / plat / asset).write_bytes(archive)
        f = tf.Fortress(channel=channel, headless=True)
        try:
            f._start_native(plat)
        except Exception:  # noqa: BLE001 - cmd.exe is absent here; the argv is the signal
            pass
        finally:
            if f._proc is not None:
                f.close()
        if cache_execs or planted.exists():
            pytest.fail(
                "Windows launcher path inside the cache was passed to the spawner "
                f"after it could be replaced: {cache_execs!r}"
            )


def _child_env(cache: Path | None, host: str, home: Path | None) -> dict[str, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SDK_PYTHON)
    env["FORTRESS_DOWNLOAD_HOST"] = host
    env.pop("FORTRESS_CHANNEL", None)
    if cache is None:
        env.pop("FORTRESS_BROWSERS_PATH", None)
    else:
        env["FORTRESS_BROWSERS_PATH"] = str(cache)
    if home is not None:
        env["HOME"] = str(home)
    return env


def _run_fresh_start(env: dict[str, str], marker: Path, port: int) -> tuple[str, str]:
    code = textwrap.dedent(
        """\
        import os, sys
        from tilion_fortress import Fortress
        marker = os.environ["MARKER"]
        port = int(os.environ["CDP_PORT"])
        f = Fortress(port=port, channel="stable", headless=True)
        try:
            f.start()
            sys.stdout.write("START_OK\\n")
        except Exception as err:
            sys.stdout.write(f"START_ERR {type(err).__name__}: {err}\\n")
        finally:
            f.close()
        sys.stdout.write("MARKER %s\\n" % ("1" if os.path.exists(marker) else "0"))
        """
    )
    env = dict(env)
    env["MARKER"] = str(marker)
    env["CDP_PORT"] = str(port)
    proc = subprocess.run(
        [sys.executable, "-c", code],
        env=env,
        cwd=str(SDK_PYTHON),
        text=True,
        capture_output=True,
        timeout=15,
        check=False,
    )
    return proc.stdout, proc.stderr


def test_env_browsers_path_is_the_cache_that_gets_executed(tmp_path):
    cache = tmp_path / "shared-browsers"
    marker = tmp_path / "env-marker"
    tag = tf._CHANNELS["stable"]["tag"]
    asset = tf._ASSETS["linux-x64"][0]
    _plant(cache, tag, "linux-x64", _cdp_script(marker))
    with ReleaseServer() as srv:
        srv.publish_mismatch(asset)
        stdout, stderr = _run_fresh_start(
            _child_env(cache, srv.host, None), marker, _free_port()
        )
    if "START_OK" in stdout or marker.exists():
        pytest.fail(
            "FORTRESS_BROWSERS_PATH launcher was executed; "
            f"stdout={stdout!r} stderr={stderr!r} hits={srv.hits!r}"
        )
    assert "START_ERR" in stdout
    assert "MARKER 0" in stdout


def test_default_home_cache_preseed_is_not_executed(tmp_path):
    home = tmp_path / "home"
    marker = tmp_path / "home-marker"
    tag = tf._CHANNELS["stable"]["tag"]
    asset = tf._ASSETS["linux-x64"][0]
    cache = home / ".cache" / "tilion-fortress"
    _plant(cache, tag, "linux-x64", _cdp_script(marker))
    with ReleaseServer() as srv:
        srv.publish_mismatch(asset)
        stdout, stderr = _run_fresh_start(
            _child_env(None, srv.host, home), marker, _free_port()
        )
    if "START_OK" in stdout or marker.exists():
        pytest.fail(
            "default ~/.cache launcher was executed; "
            f"stdout={stdout!r} stderr={stderr!r} hits={srv.hits!r}"
        )
    assert "START_ERR" in stdout
    assert "MARKER 0" in stdout


def test_cli_does_not_execute_preseeded_launcher(tmp_path):
    cache = tmp_path / "cli-browsers"
    marker = tmp_path / "cli-marker"
    tag = tf._CHANNELS["stable"]["tag"]
    asset = tf._ASSETS["linux-x64"][0]
    _plant(cache, tag, "linux-x64", _cdp_script(marker))
    port = _free_port()
    with ReleaseServer() as srv:
        srv.publish_mismatch(asset)
        env = _child_env(cache, srv.host, None)
        proc = subprocess.Popen(
            [sys.executable, "-m", "tilion_fortress", "--port", str(port)],
            env=env,
            cwd=str(SDK_PYTHON),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            ran = _wait_until(lambda: marker.exists() or proc.poll() is not None, 5)
            if marker.exists():
                pytest.fail(
                    "tilion-fortress CLI executed the planted launcher; "
                    f"hits={srv.hits!r}"
                )
            if proc.poll() is None:
                pytest.fail(f"CLI did not refuse the planted launcher (waited, ran={ran})")
            assert proc.returncode != 0
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=5)
