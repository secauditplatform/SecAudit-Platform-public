"""Tests for bundled profile catalog."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.services.profiles_catalog import (
    discover_importable_package_dirs,
    extract_benchmark_ref,
    infer_profile_family,
)


@pytest.mark.parametrize(
    "text",
    [
        "Red Hat Enterprise Linux 9 Benchmark v1.0.0",
        "Hardening for Ubuntu 22.04",
        "PCI DSS Linux checks",
        "ФСТЭК Linux",
        "Custom internal profile",
    ],
)
def test_infer_profile_family_always_custom(text: str) -> None:
    assert infer_profile_family(text) == "custom"


def test_extract_benchmark_ref_no_longer_scrapes_trademarks() -> None:
    assert extract_benchmark_ref(
        "Стандарт RHEL 9 (v1.0.0)",
        "Red_Hat_Enterprise_Linux_9_Benchmark_v1.0.0",
    ) is None


def _write_minimal_package(package_dir: Path, *, profile_name: str, version: str = "1.0") -> None:
    package_dir.mkdir(parents=True, exist_ok=True)
    (package_dir / "profile_rules.json").write_text(
        json.dumps(
            {
                "version": 1,
                "format": "secaudit.profile_rules",
                "rules": [
                    {
                        "num": "1",
                        "title": "summary",
                        "explanation": "desc",
                        "criticality": "LOW",
                        "check_script": "audit",
                        "requirement_id": "RULE0001",
                        "match_pattern": "RULE1=(.*)",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (package_dir / "audit.sh").write_text("#!/bin/bash\necho RULE1= PASS: ok\n", encoding="utf-8")
    (package_dir / "description.json").write_text(
        json.dumps(
            {
                "profile_name": profile_name,
                "version": version,
                "overview": f"{profile_name} Benchmark v{version}",
                "profile_family": "custom",
                "os": {"name": "Linux", "vendor": "Test", "version": "", "icon": "ic_linux.svg"},
                "software": {"name": profile_name, "vendor": "Test", "category": "OS", "version": version},
                "profile_rules": "profile_rules.json",
            }
        ),
        encoding="utf-8",
    )


@pytest.mark.asyncio
async def test_build_catalog_discovers_package(tmp_path: Path) -> None:
    package_dir = tmp_path / "Linux Platform" / "Demo_CRE_AI"
    _write_minimal_package(package_dir, profile_name="Demo OS")

    from secaudit_core.profiles_catalog import build_catalog_sync
    from unittest.mock import MagicMock

    db = MagicMock()
    result = MagicMock()
    result.all.return_value = []
    db.execute.return_value = result

    entries = build_catalog_sync(db, str(tmp_path))

    assert len(entries) == 1
    assert entries[0]["profile_name"] == "Demo OS"
    assert entries[0]["profile_family"] == "custom"
    assert entries[0]["imported"] is False


def test_discover_importable_package_dirs_skips_test_fixtures(tmp_path: Path) -> None:
    real_dir = tmp_path / "HAProxy_CRE_NUP(1.3.0)_AI" / "HAProxy_CRE_AI"
    _write_minimal_package(real_dir, profile_name="HAProxy", version="1.3.0")

    fixture_dir = tmp_path / "HAProxy_CRE_NUP(1.3.0)_AI" / "src" / "test" / "resources" / "input" / "std1"
    fixture_dir.mkdir(parents=True)
    (fixture_dir / "description.json").write_text(
        json.dumps({"profile_name": "std1", "version": "1.0"}),
        encoding="utf-8",
    )

    found = discover_importable_package_dirs(tmp_path)
    assert real_dir in found
    assert fixture_dir not in found
