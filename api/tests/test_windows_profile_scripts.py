"""Tests for Windows Platform profile packages and builder output."""

from __future__ import annotations

import base64
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from tests.repo_paths import profiles_root, scripts_root, secaudit_core_root

WIN_ROOT = profiles_root() / "Windows Platform"
SCRIPTS_DIR = scripts_root()

sys.path.insert(0, str(secaudit_core_root()))
sys.path.insert(0, str(SCRIPTS_DIR))

from secaudit_core.profile_packages import load_profile_package, validate_profile_package  # noqa: E402
from windows_profile_rules import decode_rules_from_script, rules_have_eval  # noqa: E402

WINDOW_PACKAGES = [
    p
    for p in sorted(WIN_ROOT.iterdir())
    if p.is_dir() and p.name != "scripts" and (p / "description.json").is_file()
]

B64_RE = re.compile(r'FromBase64String\("([^"]+)"\)')


@pytest.mark.parametrize("package_dir", WINDOW_PACKAGES, ids=[p.name for p in WINDOW_PACKAGES])
def test_windows_package_validates(package_dir: Path) -> None:
    validate_profile_package(package_dir)
    loaded = load_profile_package(package_dir)
    assert loaded["profile"].get("profile_family") == "custom"
    assert loaded["scripts"]


@pytest.mark.parametrize("package_dir", WINDOW_PACKAGES, ids=[p.name for p in WINDOW_PACKAGES])
def test_windows_rules_have_eval_metadata(package_dir: Path) -> None:
    rules = json.loads((package_dir / "profile_rules.json").read_text(encoding="utf-8"))["rules"]
    assert rules_have_eval(rules)


@pytest.mark.parametrize("package_dir", WINDOW_PACKAGES, ids=[p.name for p in WINDOW_PACKAGES])
def test_windows_embedded_rules_match_profile_rules(package_dir: Path) -> None:
    rules = json.loads((package_dir / "profile_rules.json").read_text(encoding="utf-8"))["rules"]
    script = next(package_dir.glob("*_scripts.ps1"))
    embedded = decode_rules_from_script(script)
    assert len(embedded) == len(rules)
    req_ids = {rule["requirement_id"] for rule in rules}
    assert set(embedded) == req_ids


@pytest.mark.parametrize("package_dir", WINDOW_PACKAGES, ids=[p.name for p in WINDOW_PACKAGES])
def test_windows_script_has_no_invoke_expression(package_dir: Path) -> None:
    script = next(package_dir.glob("*_scripts.ps1"))
    text = script.read_text(encoding="utf-8", errors="replace")
    assert "Invoke-Expression" not in text


@pytest.mark.parametrize("package_dir", WINDOW_PACKAGES, ids=[p.name for p in WINDOW_PACKAGES])
def test_windows_script_registry_paths(package_dir: Path) -> None:
    script = next(package_dir.glob("*_scripts.ps1"))
    text = script.read_text(encoding="utf-8", errors="replace")
    assert "CurrentControlSet.Services\\" not in text


def test_extract_registry_key_paths_from_minified_script() -> None:
    from win_profile_common import extract_registry_key_paths

    literal = extract_registry_key_paths("Get_Registry_Win10.ps1")
    assert literal.startswith("@(")
    assert "CurrentControlSet\\Services\\" in literal
    assert "CurrentControlSet.Services\\" not in literal


def test_verify_windows_platform_profiles_script() -> None:
    script = SCRIPTS_DIR / "verify_windows_platform_profiles.py"
    if not script.is_file():
        pytest.skip("verify_windows_platform_profiles.py not available")
    result = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(script.parent.parent),
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr or result.stdout


def test_windows_profile_rules_roundtrip_fields() -> None:
    sample = WIN_ROOT / "Windows11" / "profile_rules.json"
    rules = json.loads(sample.read_text(encoding="utf-8"))["rules"]
    first = rules[0]
    for field in ("operator", "target", "parser", "collector", "match_pattern"):
        assert first.get(field)
