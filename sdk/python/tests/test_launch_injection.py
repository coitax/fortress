"""Windows launch flags must not be interpreted by cmd.exe.

``Fortress._start_native`` appends persona values and ``extra_args`` to a
``cmd /c tilion.cmd ...`` argument vector. On Windows, ``subprocess.Popen``
joins that vector with ``list2cmdline`` and ``CreateProcess`` hands the
string to cmd.exe. These tests plant a launcher, run that function, and
interpret the resulting command line the way cmd.exe does (see ``win_cmd.py``).

They fail while a persona value or extra argument can introduce ``&``,
``&&``, ``|``, or an unquoted redirect. A fix passes when the injected
command is not dispatched and no redirect is performed — including when the
launch is rejected before the process is created. A file written by the
injected command is a failure even if the SDK then raises.
"""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tilion_fortress as tf  # noqa: E402


def _install_cmd(tmp_path: Path) -> Path:
    """Put the cmd.exe stand-in on PATH under the name Windows resolves ``cmd`` to."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    launcher = bindir / "cmd"
    script = Path(__file__).resolve().parent / "win_cmd.py"
    launcher.write_text(
        f"#!/bin/sh\nexec {sys.executable} {script} \"$@\"\n",
        encoding="utf-8",
    )
    launcher.chmod(launcher.stat().st_mode | stat.S_IEXEC)
    return bindir


def _plant_launcher(cache: Path, tag: str) -> Path:
    launcher = cache / tag / "win-x64" / "tilion-fortress" / "tilion.cmd"
    launcher.parent.mkdir(parents=True)
    launcher.write_text("@echo off\r\n", encoding="utf-8")
    return launcher


def _launch(monkeypatch, tmp_path: Path, **kwargs) -> Path:
    marker = tmp_path / "marker"
    bindir = _install_cmd(tmp_path)
    monkeypatch.setenv("FORTRESS_CMD_MARKER", str(marker))
    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ.get("PATH", ""))
    cache = tmp_path / "cache"
    monkeypatch.setattr(tf, "_CACHE", cache)
    fort = tf.Fortress(**kwargs)
    _plant_launcher(cache, fort._tag)
    try:
        fort._start_native("win-x64")
        if fort._proc is not None:
            fort._proc.wait(timeout=10)
    except Exception:
        pass
    finally:
        proc = fort._proc
        if proc is not None and proc.poll() is None:
            proc.kill()
            proc.wait(timeout=10)
    err = Path(str(marker) + ".err")
    if err.exists():
        raise AssertionError(err.read_text(encoding="utf-8"))
    return marker


def _assert_not_injected(marker: Path) -> None:
    detail = marker.read_text(encoding="utf-8") if marker.exists() else ""
    assert not marker.exists(), detail


def test_benign_persona_does_not_dispatch_a_second_command(tmp_path, monkeypatch):
    marker = _launch(
        monkeypatch,
        tmp_path,
        persona={"timezone": "America/New_York", "webgl_renderer": "ANGLE (NVIDIA, RTX 3060)"},
        extra_args=["--window-size=1280,800"],
        port=9,
    )
    _assert_not_injected(marker)


@pytest.mark.parametrize("field,value", [
    ("timezone", "UTC&pwned"),
    ("languages", "en-US&pwned"),
    ("webgl_renderer", "ANGLE&pwned"),
    ("webgl_vendor", "Google&pwned"),
    ("platform", "Win32&pwned"),
])
def test_persona_value_separator_is_not_a_second_command(tmp_path, monkeypatch, field, value):
    marker = _launch(monkeypatch, tmp_path, persona={field: value}, port=9)
    _assert_not_injected(marker)


@pytest.mark.parametrize("payload", ["UTC&&pwned", "UTC|pwned", "UTC>pwned.txt", "UTC<pwned.txt"])
def test_persona_metacharacters_are_not_executed(tmp_path, monkeypatch, payload):
    marker = _launch(monkeypatch, tmp_path, persona={"timezone": payload}, port=9)
    _assert_not_injected(marker)


def test_extra_args_separator_is_not_a_second_command(tmp_path, monkeypatch):
    marker = _launch(monkeypatch, tmp_path, extra_args=["--proxy-server=127.0.0.1&pwned"], port=9)
    _assert_not_injected(marker)


def test_extra_args_element_that_is_only_a_separator_is_not_executed(tmp_path, monkeypatch):
    marker = _launch(monkeypatch, tmp_path, extra_args=["&pwned"], port=9)
    _assert_not_injected(marker)


def test_unknown_persona_key_shares_the_same_command_line(tmp_path, monkeypatch):
    marker = _launch(monkeypatch, tmp_path, persona={"audio_seed": "1&pwned"}, port=9)
    _assert_not_injected(marker)


def test_spaced_separator_inside_one_argument_stays_quoted(tmp_path, monkeypatch):
    # list2cmdline quotes an argument that contains a space, so cmd.exe keeps
    # the ampersand inside that argument. This is the boundary the unquoted
    # payloads above cross; it must keep passing after a fix.
    marker = _launch(
        monkeypatch,
        tmp_path,
        persona={"webgl_renderer": "ANGLE (NVIDIA) & pwned"},
        port=9,
    )
    _assert_not_injected(marker)
