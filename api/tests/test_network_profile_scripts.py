"""Tests for Network Platform profile packages."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from tests.repo_paths import profiles_root, scripts_root, secaudit_core_root

NETWORK_ROOT = profiles_root() / "Network Platform"
FIXTURES = NETWORK_ROOT / "_fixtures"

sys.path.insert(0, str(secaudit_core_root()))

from secaudit_core.profile_packages import load_profile_package, validate_profile_package  # noqa: E402

NETWORK_PACKAGES = [
    p
    for p in sorted(NETWORK_ROOT.iterdir())
    if p.is_dir() and p.name != "_shared" and (p / "description.json").is_file()
]

PASS_FAIL_RE = re.compile(r"\b(PASS|FAIL|SKIP|ERROR)\b", re.IGNORECASE)


@pytest.mark.parametrize("package_dir", NETWORK_PACKAGES, ids=[p.name for p in NETWORK_PACKAGES])
def test_network_package_validates(package_dir: Path) -> None:
    validate_profile_package(package_dir)
    loaded = load_profile_package(package_dir)
    assert loaded["category_slug"] == "network-platform"
    assert loaded["scripts"]


@pytest.mark.parametrize("package_dir", NETWORK_PACKAGES, ids=[p.name for p in NETWORK_PACKAGES])
def test_network_compliance_playbook_present(package_dir: Path) -> None:
    meta = json.loads((package_dir / "description.json").read_text(encoding="utf-8"))
    playbook = meta.get("compliance_playbook")
    assert playbook, "compliance_playbook missing"
    assert (package_dir / playbook).is_file()


@pytest.mark.parametrize("package_dir", NETWORK_PACKAGES, ids=[p.name for p in NETWORK_PACKAGES])
def test_network_script_emits_pass_fail(package_dir: Path) -> None:
    if package_dir.name == "Continent_4_CRE_NUP":
        pytest.skip("Continent requires live API fixture")
    fixture = None
    if package_dir.name == "MikroTik":
        fixture = FIXTURES / "mikrotik_export.txt"
    elif package_dir.name == "Cisco_IOS_15":
        fixture = FIXTURES / "cisco_ios_running_config.txt"
    if fixture is None or not fixture.is_file():
        pytest.skip("no offline fixture for package")
    script = next(
        p
        for p in package_dir.glob("*.py")
        if p.name not in {"remote_access.py", "network_checks.py"} and "_remediation" not in p.name
    )
    env = {
        **dict(**__import__("os").environ),
        "SECAUDIT_CONFIG_FILE": str(fixture),
        "SECAUDIT_PREFER_CONFIG_FILE": "1",
    }
    proc = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(package_dir),
        capture_output=True,
        text=True,
        timeout=45,
        env=env,
    )
    assert proc.returncode == 0, proc.stderr
    assert PASS_FAIL_RE.search(proc.stdout), proc.stdout[:500]


def test_verify_network_platform_profiles_script() -> None:
    script = scripts_root() / "verify_network_platform_profiles.py"
    if not script.is_file():
        pytest.skip("verify_network_platform_profiles.py not available")
    proc = subprocess.run(
        [sys.executable, str(script)],
        cwd=str(script.parent.parent),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
