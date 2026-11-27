"""Stand-in for the Windows cmd.exe launch line the SDKs build.

The product cannot be executed on Windows in this environment. The launch
tests still run the real SDK spawn, then interpret the command line with the
same transforms the Windows runtime applies:

* CPython ``subprocess.list2cmdline`` (``subprocess.py``) when ``shell`` is
  false, which is what ``Popen`` does before ``CreateProcess`` on Windows.
* A space join when Node has already built ``cmd.exe /d /s /c "..."`` with
  ``windowsVerbatimArguments`` (libuv copies those argv elements verbatim).
* cmd.exe's ``/c`` quote stripping and ``&``, ``&&``, ``|``, ``||``, ``<``,
  and ``>`` handling, transcribed from Wine 10.0 ``programs/cmd/wcmdmain.c``
  (``WCMD_strip_quotes``, the ``/c`` ``/s`` switch loop, ``WCMD_IsEndQuote``,
  and the ``WCMD_ReadAndParseLine`` separator cases). Microsoft's cmd
  documentation describes the same ``/s`` strip and the same operators.

This process does not run the attacker command. It records that cmd.exe would
have dispatched one, by writing the marker path in ``FORTRESS_CMD_MARKER``.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def _is_end_quote(quote: str, quote_index: int) -> bool:
    """Wine ``WCMD_IsEndQuote``: ``quote`` starts at the quote under test."""
    if quote_index == 0:
        return False
    quote_count = quote_index
    for ch in quote:
        if ch == '"':
            quote_count += 1
        elif (quote_count % 2) == 0 and ch in "<>|& ":
            break
    return quote_index >= (quote_count // 2)


def _strip_quotes(cmd: str) -> str:
    """Wine ``WCMD_strip_quotes``: drop the first quote and the last quote."""
    if not cmd.startswith('"'):
        return cmd
    dest: list[str] = []
    lastq = None
    for ch in cmd[1:]:
        if ch == '"':
            lastq = len(dest)
        dest.append(ch)
    if lastq is not None:
        del dest[lastq]
    return "".join(dest)


def _executable_exists(token: str) -> bool:
    """Wine's "does this /c executable exist?" check, on the local filesystem."""
    if not token:
        return False
    if os.path.exists(token):
        return True
    root, ext = os.path.splitext(token)
    if ext:
        return False
    for suffix in (".bat", ".com", ".cmd", ".exe"):
        if os.path.exists(token + suffix):
            return True
    return False


def _first_token(cmd: str) -> str:
    cmd = cmd.strip()
    if not cmd:
        return ""
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        return cmd[1:end] if end > 1 else cmd.strip('"')
    return cmd.split()[0]


def _apply_quote_mode(cmd: str, opt_s: bool) -> str:
    """Wine's ``/c`` quote mode. ``/s`` forces the old strip-first-and-last rule."""
    if not opt_s:
        q1 = cmd.find('"')
        if q1 < 0:
            opt_s = True
        else:
            q2 = cmd.find('"', q1 + 1)
            if q2 < 0 or '"' in cmd[q2 + 1:]:
                opt_s = True
            else:
                opt_s = True
                for ch in cmd[q1:q2]:
                    if ch in "&<>()@^|":
                        opt_s = True
                        break
                    if ch in " \t":
                        opt_s = False
                if not opt_s and not _executable_exists(cmd[q1 + 1:q2]):
                    opt_s = True
    if opt_s and cmd.startswith('"'):
        cmd = _strip_quotes(cmd)
    return cmd


def command_after_switch(cmdline: str) -> str:
    """Return the ``/c`` or ``/k`` command string after Wine's quote processing."""
    opt_c = opt_k = opt_s = False
    n = len(cmdline)
    i = 0
    while i < n and cmdline[i] != "/":
        i += 1
    arg = i
    found = False
    while arg < n:
        if cmdline[arg] != "/":
            arg += 1
            continue
        sw = cmdline[arg + 1].lower() if arg + 1 < n else ""
        if sw == "c":
            opt_c = True
        elif sw == "k":
            opt_k = True
        elif sw == "s":
            opt_s = True
        if opt_c or opt_k:
            arg += 2
            found = True
            break
        arg += 1
    if not found:
        return cmdline
    while arg < n and cmdline[arg] in " \t,=;":
        arg += 1
    return _apply_quote_mode(cmdline[arg:], opt_s)


def split_commands(line: str) -> tuple[list[tuple[str | None, str]], bool]:
    """Split on unquoted cmd separators. Also report an unquoted redirect.

    Operator on each entry is the separator that preceded it (``None`` for the
    first command). ``2>&1`` stays inside the command, matching Wine's rule
    that an ampersand immediately after ``>`` is not a command separator.
    """
    commands: list[tuple[str | None, str]] = []
    buf: list[str] = []
    in_quotes = 0
    redirected = False
    op_for_next: str | None = None
    i = 0

    def push() -> None:
        nonlocal op_for_next
        commands.append((op_for_next, "".join(buf)))
        buf.clear()

    while i < len(line):
        ch = line[i]
        if ch == '"':
            if _is_end_quote(line[i:], in_quotes):
                in_quotes -= 1
            else:
                in_quotes += 1
            buf.append(ch)
            i += 1
            continue
        if ch == "^" and in_quotes == 0:
            if i + 1 < len(line):
                buf.append(line[i + 1])
                i += 2
            else:
                i += 1
            continue
        if in_quotes == 0 and ch in "<>":
            if ch == ">" and i + 1 < len(line) and line[i + 1] == "&":
                buf.append(">&")
                i += 2
                continue
            redirected = True
            buf.append(ch)
            i += 1
            continue
        if in_quotes == 0 and ch == "&":
            if i + 1 < len(line) and line[i + 1] == "&":
                push()
                op_for_next = "&&"
                i += 2
            else:
                push()
                op_for_next = "&"
                i += 1
            continue
        if in_quotes == 0 and ch == "|":
            if i + 1 < len(line) and line[i + 1] == "|":
                push()
                op_for_next = "||"
                i += 2
            else:
                push()
                op_for_next = "|"
                i += 1
            continue
        buf.append(ch)
        i += 1
    push()
    return commands, redirected


def dispatched_commands(cmdline: str) -> tuple[list[str], bool]:
    """Commands cmd.exe would start, plus whether an unquoted redirect ran.

    ``&&`` runs the next command only after a zero exit. A command whose first
    token exists on disk is treated as success (the planted ``tilion.cmd``);
    anything else is a failure. ``||`` is the opposite. ``&`` and ``|`` always
    start the next command. An empty command is not a dispatch.
    """
    body = command_after_switch(cmdline)
    parts, redirected = split_commands(body)
    started: list[str] = []
    status = 1
    for index, (op, text) in enumerate(parts):
        if index == 0:
            started.append(text)
            status = 0 if _executable_exists(_first_token(text)) else 1
            continue
        run = (
            op in ("&", "|")
            or (op == "&&" and status == 0)
            or (op == "||" and status != 0)
        )
        if not run or not text.strip():
            if op == "&&" and status != 0:
                continue
            if op == "||" and status == 0:
                continue
            continue
        started.append(text)
        status = 0 if _executable_exists(_first_token(text)) else 1
    extra = [text for text in started[1:] if text.strip()]
    return extra, redirected


def cmdline_from_posix_argv(argv: list[str]) -> str:
    """Rebuild the Windows command line from the argv the SDK actually passed.

    Node's Windows ``shell: true`` path has already produced
    ``['cmd.exe', '/d', '/s', '/c', '"<joined>"']``. POSIX ``exec`` rewrites
    argv[0] to the resolved stand-in path; libuv's verbatim join uses the
    ``cmd.exe`` token Node placed in the argv array. Python passes
    ``['cmd', '/c', launcher, *flags]`` and Windows joins that with
    ``list2cmdline`` before ``CreateProcess``.
    """
    if argv[1:4] == ["/d", "/s", "/c"]:
        return " ".join(["cmd.exe", *argv[1:]])
    return subprocess.list2cmdline(["cmd", *argv[1:]])


def record_if_injected(cmdline: str, marker: str | None) -> bool:
    """Write ``marker`` when cmd.exe would run something besides the launcher."""
    extra, redirected = dispatched_commands(cmdline)
    if not marker or not (extra or redirected):
        return bool(extra or redirected)
    detail = []
    if extra:
        detail.append("extra commands: " + " | ".join(extra))
    if redirected:
        detail.append("unquoted redirect")
    Path(marker).write_text("\n".join(detail) + "\n", encoding="utf-8")
    return True


def main(argv: list[str]) -> int:
    marker = os.environ.get("FORTRESS_CMD_MARKER")
    try:
        cmdline = cmdline_from_posix_argv(argv)
        record_if_injected(cmdline, marker)
    except Exception:
        err = Path(str(marker) + ".err") if marker else None
        import traceback
        text = traceback.format_exc()
        if err is not None:
            err.write_text(text, encoding="utf-8")
        else:
            sys.stderr.write(text)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
