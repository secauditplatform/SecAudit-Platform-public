"""Tests for optional compliance playbook packaging and versioning."""

from __future__ import annotations

import json
from pathlib import Path

from secaudit_core.profile_packages import (
    discover_check_scripts,
    load_playbook_changelog,
    load_profile_package,
    read_compliance_playbook,
    resolve_compliance_playbook_path,
    update_compliance_playbook_in_package,
    validate_profile_package,
)


MINIMAL_PLAYBOOK = """---
- name: Demo compliance
  hosts: all
  gather_facts: false
  tasks:
    - name: Ping
      ansible.builtin.ping:
"""


def _write_package(root: Path, *, with_compliance: bool = True) -> Path:
    package_dir = root / "DemoPkg"
    package_dir.mkdir()
    meta = {
        "profile_name": "Demo Compliance Playbook",
        "is_active": True,
        "version": "1.0",
        "os": {"name": "Linux", "vendor": "Demo", "version": "1"},
        "profile_rules": "profile_rules.json",
    }
    if with_compliance:
        meta["compliance_playbook"] = "demo_compliance.yml"
        meta["compliance_playbook_version"] = "1.0"
        (package_dir / "demo_compliance.yml").write_text(MINIMAL_PLAYBOOK, encoding="utf-8")
    (package_dir / "description.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    (package_dir / "profile_rules.json").write_text(
        json.dumps(
            {
                "version": 1,
                "format": "secaudit.profile_rules",
                "rules": [
                    {
                        "num": "1",
                        "title": "Demo",
                        "requirement_id": "RULE0001",
                        "check_script": "demo_scripts",
                        "match_pattern": "RULE1=(.*)",
                    }
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    (package_dir / "demo_scripts.sh").write_text("#!/bin/sh\necho RULE1=PASS:\n", encoding="utf-8")
    return package_dir


def test_compliance_playbook_excluded_from_check_scripts(tmp_path: Path) -> None:
    package_dir = _write_package(tmp_path, with_compliance=True)
    validate_profile_package(package_dir)
    loaded = load_profile_package(package_dir)
    names = {item["name"] for item in loaded["scripts"]}
    assert names == {"demo_scripts"}
    assert "demo_compliance" not in names
    path = resolve_compliance_playbook_path(package_dir, loaded["profile"])
    assert path is not None
    assert path.name == "demo_compliance.yml"


def test_convention_compliance_filename_resolved(tmp_path: Path) -> None:
    package_dir = _write_package(tmp_path, with_compliance=False)
    (package_dir / "Alma_10_compliance.yml").write_text(MINIMAL_PLAYBOOK, encoding="utf-8")
    meta = json.loads((package_dir / "description.json").read_text(encoding="utf-8"))
    scripts = discover_check_scripts(package_dir, meta)
    assert all(item["name"] != "Alma_10_compliance" for item in scripts)
    resolved = resolve_compliance_playbook_path(package_dir, meta)
    assert resolved is not None
    assert resolved.name == "Alma_10_compliance.yml"


def test_update_compliance_playbook_bumps_version_and_changelog(tmp_path: Path) -> None:
    package_dir = _write_package(tmp_path, with_compliance=True)
    updated = update_compliance_playbook_in_package(
        package_dir,
        MINIMAL_PLAYBOOK + "\n# edited\n",
        actor="tester",
    )
    assert updated["playbook_version"] == "1.1"
    assert updated["playbook_version_before"] == "1.0"
    payload = read_compliance_playbook(package_dir)
    assert payload is not None
    assert payload["version"] == "1.1"
    assert "# edited" in payload["content"]
    changelog = load_playbook_changelog(package_dir)
    assert len(changelog) == 1
    assert changelog[0]["actor"] == "tester"
    assert changelog[0]["playbook_version_after"] == "1.1"
    meta = json.loads((package_dir / "description.json").read_text(encoding="utf-8"))
    assert meta["compliance_playbook_version"] == "1.1"
