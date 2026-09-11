"""Package script path containment."""

from pathlib import Path

import pytest

from secaudit_core.package_paths import resolve_script_under_package


def test_resolve_script_accepts_relative_path(tmp_path: Path):
    package = tmp_path / "pkg"
    scripts = package / "scripts"
    scripts.mkdir(parents=True)
    script = scripts / "check.sh"
    script.write_text("#!/bin/sh\n", encoding="utf-8")

    resolved = resolve_script_under_package(package, "scripts/check.sh")
    assert resolved == script.resolve()


def test_resolve_script_rejects_parent_segments(tmp_path: Path):
    package = tmp_path / "pkg"
    package.mkdir()
    with pytest.raises(ValueError):
        resolve_script_under_package(package, "foo/../../etc/passwd")
