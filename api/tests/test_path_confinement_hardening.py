"""Path confinement for SCAP metadata refs and tar upload extraction."""

from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from app.services.interpreter import _safe_extract_tar
from secaudit_core.oscap import (
    resolve_oval_path,
    resolve_scap_benchmark_path,
    resolve_scap_content_files,
)


def test_resolve_scap_benchmark_rejects_absolute_ref(tmp_path: Path):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "description.json").write_text(
        json.dumps({"scap_xccdf_path": "/etc/passwd"}),
        encoding="utf-8",
    )
    assert resolve_scap_benchmark_path(package) is None


def test_resolve_oval_rejects_traversal(tmp_path: Path):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "description.json").write_text(
        json.dumps({"scap_oval_path": "../outside.xml"}),
        encoding="utf-8",
    )
    assert resolve_oval_path(package) is None


def test_resolve_scap_extra_files_skips_escape(tmp_path: Path):
    package = tmp_path / "pkg"
    package.mkdir()
    bench = package / "scap_benchmark.xml"
    bench.write_text("<Benchmark/>", encoding="utf-8")
    safe = package / "extra.xml"
    safe.write_text("<oval/>", encoding="utf-8")
    (package / "description.json").write_text(
        json.dumps({"scap_extra_files": ["extra.xml", "/etc/passwd", "../x.xml"]}),
        encoding="utf-8",
    )
    files = resolve_scap_content_files(package, bench)
    names = {path.name for path in files}
    assert "extra.xml" in names
    assert "passwd" not in names


def test_safe_extract_tar_rejects_symlink(tmp_path: Path):
    dest = tmp_path / "out"
    dest.mkdir()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as archive:
        info = tarfile.TarInfo(name="link-out")
        info.type = tarfile.SYMTYPE
        info.linkname = "/etc/passwd"
        archive.addfile(info)
    buf.seek(0)
    with tarfile.open(fileobj=buf, mode="r") as archive:
        with pytest.raises(ValueError, match="Unsafe archive member"):
            _safe_extract_tar(archive, dest)
