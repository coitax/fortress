"""extract_document must not return bytes from outside the MCP write directory.

Local sources are handed to the document extractor with no basename or directory
confinement, so an absolute path, a parent-directory segment, or a symlink that
points outside the write directory comes back as extracted text. These tests
assert the confined behavior. They fail while that path is open and pass once
reads accept only a basename under TILION_MCP_WRITE_DIR (the same directory
writes use), reject absolute paths and parent segments, and do not follow a
symlink to a file outside that directory. URL sources stay on the http guard.

The Fortress process is not launched. Tilion.start() only uses it to set the
local-mode flag; the document path is not an argument to that launch. The
extractor that opens the file is the installed tilion package.

Run (from the repo root, against the commit that still has the unsandboxed read):

    pip install --no-deps 'tilion==0.1.12'
    pip install 'mcp>=1.28,<1.29' 'aiohttp>=3.9' 'beautifulsoup4>=4.12' \
        pdfminer.six openpyxl python-docx pytest
    pytest tests/test_extract_document_confinement.py -q
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import types
import uuid
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[1]
# The repo's mcp/ directory must not shadow the installed MCP SDK.
sys.path[:] = [p for p in sys.path if Path(p or ".").resolve() != _REPO]


def _install_engine_stub() -> None:
    """Satisfy Tilion.start()'s engine import without launching a browser.

    start() constructs Fortress and connects over CDP, then sets the local-mode
    flag extract_file checks. Neither call receives the document source.
    """
    if "tilion_fortress" in sys.modules and hasattr(sys.modules["tilion_fortress"], "Fortress"):
        # A previous import may already be the real package. Replace it so start()
        # does not download or boot the engine during this test module.
        pass
    fake = types.ModuleType("tilion_fortress")

    class Fortress:
        def __init__(self, *args, **kwargs):
            self.cdp_url = "http://127.0.0.1:9"

        def start(self):
            return self

        def close(self):
            return None

    fake.Fortress = Fortress
    sys.modules["tilion_fortress"] = fake


_install_engine_stub()

import importlib.util

_spec = importlib.util.spec_from_file_location(
    "fortress_mcp_server_under_test", _REPO / "mcp" / "server.py"
)
server = importlib.util.module_from_spec(_spec)
assert _spec.loader is not None
_spec.loader.exec_module(server)

from tilion.core.browser import Browser


async def _connect_without_engine(cls, url, config=None):
    return types.SimpleNamespace(is_started=True, tabs=[])


Browser.connect = classmethod(_connect_without_engine)


def _marker(label: str) -> str:
    return f"MARKER_{label}_{uuid.uuid4().hex}"


def _rendered(result) -> str:
    return json.dumps(result, default=str)


def _snapshot(root: Path) -> list[tuple]:
    rows = []
    if not root.exists():
        return rows
    for path in sorted(root.rglob("*")):
        if path.is_symlink() or path.is_file():
            st = path.lstat()
            rows.append((str(path.relative_to(root)), st.st_mode, st.st_size, st.st_mtime_ns))
    return rows


def _write_document(path: Path, marker: str, kind: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if kind in ("csv", "xls"):
        path.write_text(f"column\n{marker}\n", encoding="utf-8")
    elif kind in ("html", "htm"):
        path.write_text(
            f"<html><body><p>{marker}</p></body></html>", encoding="utf-8"
        )
    elif kind == "xlsx":
        from openpyxl import Workbook

        book = Workbook()
        book.active["A1"] = marker
        book.save(path)
    elif kind == "docx":
        from docx import Document

        document = Document()
        document.add_paragraph(marker)
        document.save(path)
    elif kind == "pdf":
        stream = f"BT /F1 24 Tf 72 720 Td ({marker}) Tj ET".encode()
        objects = [
            b"1 0 obj<< /Type /Catalog /Pages 2 0 R >>endobj\n",
            b"2 0 obj<< /Type /Pages /Kids [3 0 R] /Count 1 >>endobj\n",
            b"3 0 obj<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Contents 4 0 R /Resources<< /Font<< /F1 5 0 R >> >> >>endobj\n",
            b"4 0 obj<< /Length %d >>stream\n" % len(stream) + stream + b"\nendstream\nendobj\n",
            b"5 0 obj<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>endobj\n",
        ]
        path.write_bytes(b"%PDF-1.4\n" + b"".join(objects) + b"trailer<< /Root 1 0 R >>\n%%EOF\n")
    else:
        raise AssertionError(f"unknown document kind {kind}")


def _use_write_root(root: Path) -> Path:
    os.environ["TILION_MCP_WRITE_DIR"] = str(root)
    os.environ["TILLION_MCP_WRITE_DIR"] = str(root)
    os.environ["TILION_MCP_ALLOW_ANY_PATH"] = "0"
    os.environ["TILLION_MCP_ALLOW_ANY_PATH"] = "0"
    resolved = Path(server._write_root())
    assert resolved == root.resolve()
    return resolved


def _call(source: str):
    # _t() caches an asyncio.Lock bound to the loop that created it.
    server._tilion = None
    server._lock = None
    try:
        return asyncio.run(server.extract_document(source))
    except Exception as exc:  # a refusal may raise instead of returning a dict
        return {"status": "error", "error": f"{type(exc).__name__}: {exc}"}


def _assert_withheld(result, marker: str) -> None:
    rendered = _rendered(result)
    if "not installed" in rendered.lower():
        raise AssertionError(
            "document parser dependency is missing, so this run never reached "
            f"the file read: {rendered[:400]}"
        )
    assert marker not in rendered, rendered[:1500]


# Every extension extract_file routes to a parser that returns file text.
_KINDS = [
    ("csv", ".csv"),
    ("xls", ".xls"),  # MIME application/vnd.ms-excel is routed to the CSV parser
    ("html", ".html"),
    ("htm", ".htm"),
    ("xlsx", ".xlsx"),
    ("docx", ".docx"),
    ("pdf", ".pdf"),
]


@pytest.fixture
def roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    write_root = tmp_path / "write"
    outside = tmp_path / "outside"
    work = tmp_path / "work"
    write_root.mkdir()
    outside.mkdir()
    work.mkdir()
    monkeypatch.chdir(work)
    _use_write_root(write_root)
    return types.SimpleNamespace(write=write_root, outside=outside, work=work)


@pytest.mark.parametrize("kind,suffix", _KINDS, ids=[k for k, _ in _KINDS])
def test_absolute_path_outside_write_root_is_not_returned(roots, kind, suffix):
    marker = _marker(kind)
    target = roots.outside / f"secret{suffix}"
    _write_document(target, marker, kind)
    before_outside = _snapshot(roots.outside)
    before_write = _snapshot(roots.write)
    result = _call(str(target))
    _assert_withheld(result, marker)
    assert _snapshot(roots.outside) == before_outside
    assert _snapshot(roots.write) == before_write


def test_absolute_csv_with_uppercase_suffix_is_not_returned(roots):
    marker = _marker("CSV")
    target = roots.outside / "secret.CSV"
    _write_document(target, marker, "csv")
    _assert_withheld(_call(str(target)), marker)


def test_absolute_path_inside_write_root_is_rejected(roots):
    marker = _marker("inside")
    target = roots.write / "note.csv"
    _write_document(target, marker, "csv")
    _assert_withheld(_call(str(target)), marker)


def test_parent_segment_cannot_escape_write_root(roots):
    marker = _marker("dotdot")
    target = roots.outside / "secret.csv"
    _write_document(target, marker, "csv")
    escaped = str(roots.write / ".." / "outside" / "secret.csv")
    assert ".." in escaped
    before = _snapshot(roots.outside)
    _assert_withheld(_call(escaped), marker)
    assert _snapshot(roots.outside) == before


def test_relative_parent_segment_cannot_escape_write_root(roots, monkeypatch):
    marker = _marker("reldot")
    target = roots.outside / "secret.csv"
    _write_document(target, marker, "csv")
    monkeypatch.chdir(roots.write)
    _assert_withheld(_call("../outside/secret.csv"), marker)


def test_parent_segment_is_rejected_when_it_resolves_inside(roots, monkeypatch):
    marker = _marker("inside_dot")
    _write_document(roots.write / "note.csv", marker, "csv")
    (roots.write / "nested").mkdir()
    monkeypatch.chdir(roots.write)
    _assert_withheld(_call("nested/../note.csv"), marker)


def test_directory_prefix_is_not_accepted(roots, monkeypatch):
    marker = _marker("nested")
    _write_document(roots.write / "nested" / "note.csv", marker, "csv")
    monkeypatch.chdir(roots.write)
    _assert_withheld(_call("nested/note.csv"), marker)


def test_symlink_basename_outside_write_root_is_not_followed(roots, monkeypatch):
    marker = _marker("link")
    target = roots.outside / "secret.csv"
    _write_document(target, marker, "csv")
    link = roots.write / "alias.csv"
    link.symlink_to(target)
    monkeypatch.chdir(roots.write)
    before = _snapshot(roots.outside)
    _assert_withheld(_call("alias.csv"), marker)
    assert _snapshot(roots.outside) == before


def test_symlink_directory_under_write_root_is_not_followed(roots):
    marker = _marker("dirlink")
    target = roots.outside / "secret.csv"
    _write_document(target, marker, "csv")
    (roots.write / "linked").symlink_to(roots.outside, target_is_directory=True)
    escaped = str(roots.write / "linked" / "secret.csv")
    _assert_withheld(_call(escaped), marker)


def test_basename_reads_the_sandbox_copy_not_the_cwd_copy(roots, monkeypatch):
    inside = _marker("sandbox")
    cwd_marker = _marker("cwd")
    _write_document(roots.write / "note.csv", inside, "csv")
    _write_document(roots.work / "note.csv", cwd_marker, "csv")
    monkeypatch.chdir(roots.work)
    result = _call("note.csv")
    rendered = _rendered(result)
    assert inside in rendered, rendered[:1500]
    assert cwd_marker not in rendered


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1/secret.csv",
        "https://127.0.0.1/secret.csv",
        "http://localhost/secret.csv",
    ],
)
def test_url_sources_stay_on_the_private_address_guard(roots, url):
    marker = _marker("url")
    _write_document(roots.outside / "secret.csv", marker, "csv")
    result = _call(url)
    rendered = _rendered(result)
    assert marker not in rendered
    assert result.get("status") == "error"
    assert "refused" in str(result.get("error", "")).lower()
