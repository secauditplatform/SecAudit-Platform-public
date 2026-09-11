"""Tests for profile_rules.json support (CSV-free packages)."""

from __future__ import annotations

import json
from pathlib import Path

from secaudit_core.profile_packages import (
    bump_semver_patch,
    load_profile_package,
    load_profile_rules_metadata,
    load_rule_changelog,
    normalize_playbook_version,
    update_profile_rule_in_package,
    validate_profile_package,
)


def _write_json_package(root: Path) -> Path:
    package_dir = root / "DemoPkg"
    package_dir.mkdir()
    (package_dir / "description.json").write_text(
        json.dumps(
            {
                "tech_name": "Demo JSON Rules",
                "label": "Demo JSON Rules",
                "is_active": True,
                "version": "1.0",
                "os": {"name": "Linux", "vendor": "Demo", "version": "1"},
                "profile_rules": "profile_rules.json",
            },
            ensure_ascii=False,
        ),
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
                        "title": "Demo summary",
                        "explanation": "Demo description",
                        "criticality": "MEDIUM",
                        "check_script": "demo_scripts",
                        "requirement_id": "RULE0001",
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


def test_profile_rules_json_package_loads(tmp_path: Path) -> None:
    package_dir = _write_json_package(tmp_path)
    validate_profile_package(package_dir)
    loaded = load_profile_package(package_dir)
    meta = load_profile_rules_metadata(package_dir)

    assert loaded["profile"]["profile_rules"] == "profile_rules.json"
    assert len(loaded["scripts"]) == 1
    assert loaded["scripts"][0]["name"] == "demo_scripts"
    assert loaded["scripts"][0]["context"] == [
        {"regex": "RULE1=(.*)", "extractionType": "SINGLE", "techName": "RULE0001"}
    ]
    assert len(meta) == 1
    assert meta[0]["requirement_id"] == "RULE0001"
    # Derived for API/DB compatibility when JSON omits tech_name.
    assert meta[0]["tech_name"] == "RULE0001"
    assert meta[0]["title"] == "Demo summary"
    assert meta[0]["explanation"] == "Demo description"
    assert meta[0]["criticality"] == "MEDIUM"
    assert meta[0]["check_script"] == "demo_scripts"
    assert "summary" not in meta[0]


def test_persist_rule_rows_dedupes_requirement_ids(tmp_path: Path) -> None:
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import sessionmaker

    from secaudit_core.models import Base, Category, CategoryType, Profile, Rule
    from secaudit_core.profiles_sync import _persist_rule_rows

    package_dir = tmp_path / "DupPkg"
    package_dir.mkdir()
    (package_dir / "description.json").write_text(
        json.dumps(
            {
                "tech_name": "Dup Rules",
                "label": "Dup Rules",
                "version": "1.0",
                "os": {"name": "Linux", "vendor": "Demo", "version": "1"},
                "profile_rules": "profile_rules.json",
            }
        ),
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
                        "requirement_id": "RULE0001",
                        "title": "One",
                        "check_script": "demo",
                        "match_pattern": "RULE1=(.*)",
                    },
                    {
                        "num": "2",
                        "requirement_id": "RULE0001",
                        "title": "Two",
                        "check_script": "demo",
                        "match_pattern": "RULE1=(.*)",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    (package_dir / "demo.sh").write_text("#!/bin/sh\necho RULE1= PASS:\n", encoding="utf-8")

    engine = create_engine(f"sqlite:///{tmp_path / 'dedupe.db'}")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    with SessionLocal() as db:
        category = Category(name="Linux Platform", slug="linux-platform", category_type=CategoryType.OS)
        db.add(category)
        db.flush()
        profile = Profile(
            profile_name="Dup Rules",
            version="1.0",
            category_id=category.id,
            package_path=str(package_dir),
            source_format="custom",
        )
        db.add(profile)
        db.flush()
        _persist_rule_rows(db, profile, package_dir)
        db.commit()
        names = sorted(db.scalars(select(Rule.tech_name).where(Rule.profile_id == profile.id)).all())
        titles = sorted(db.scalars(select(Rule.title).where(Rule.profile_id == profile.id)).all())
    engine.dispose()
    assert names == ["RULE0001", "RULE0001_2"]
    assert titles == ["One", "Two"]


def test_bump_semver_patch() -> None:
    assert bump_semver_patch("1.0.0") == "1.0.1"
    assert bump_semver_patch("1.3") == "1.4"
    assert bump_semver_patch("v2") == "v2.1"
    assert bump_semver_patch("") == "1.1"
    assert bump_semver_patch("1.0") == "1.1"


def test_normalize_playbook_version() -> None:
    assert normalize_playbook_version("1.0.0") == "1.0"
    assert normalize_playbook_version("1.0.1") == "1.0"
    assert normalize_playbook_version("1.1.0") == "1.0"
    assert normalize_playbook_version(None) == "1.0"
    assert normalize_playbook_version("1.1") == "1.1"
    assert bump_semver_patch(normalize_playbook_version("1.0.0")) == "1.1"


def test_update_profile_rule_in_package(tmp_path: Path) -> None:
    package_dir = _write_json_package(tmp_path)
    result = update_profile_rule_in_package(
        package_dir,
        "RULE0001",
        {"explanation": "Updated description", "impact": "High risk"},
        actor="tester",
    )

    assert result["profile_version"] == "1.1"
    assert result["rule"]["explanation"] == "Updated description"
    assert result["rule"]["impact"] == "High risk"
    assert "explanation" in result["changes"]
    assert "impact" in result["changes"]

    meta = json.loads((package_dir / "description.json").read_text(encoding="utf-8"))
    assert meta["version"] == "1.1"

    changelog = load_rule_changelog(package_dir)
    assert len(changelog) == 1
    assert changelog[0]["requirement_id"] == "RULE0001"
    assert changelog[0]["actor"] == "tester"
    assert changelog[0]["profile_version_after"] == "1.1"

    stored = json.loads((package_dir / "profile_rules.json").read_text(encoding="utf-8"))
    rule = stored["rules"][0]
    assert rule["explanation"] == "Updated description"
    assert rule["impact"] == "High risk"
    assert "description" not in rule
    assert "risk" not in rule
