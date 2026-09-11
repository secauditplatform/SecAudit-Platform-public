"""Tests for scheduled profiles catalog sync."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from secaudit_core.models import Base, Category, CategoryType, Profile
from secaudit_core.settings import SecAuditSettings
from secaudit_core.profiles_sync import sync_profiles_catalog


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


@pytest.fixture
def sync_db(tmp_path: Path):
    db_path = tmp_path / "sync.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    with SessionLocal() as session:
        session.add(
            Category(
                name="Linux Platform",
                slug="linux-platform",
                category_type=CategoryType.OS,
            )
        )
        session.commit()
    yield SessionLocal
    engine.dispose()


def test_sync_profiles_catalog_imports_new_custom_package(tmp_path: Path, sync_db) -> None:
    mount_root = tmp_path / "profiles"
    storage_root = tmp_path / "storage"
    package_dir = mount_root / "Linux Platform" / "Demo_CRE_AI"
    _write_minimal_package(package_dir, profile_name="Demo OS")

    settings = SecAuditSettings(
        profiles_path=str(mount_root),
        profiles_storage_path=str(storage_root),
    )

    with sync_db() as db:
        result = sync_profiles_catalog(db, settings)
        db.commit()

    assert result["count"] == 1
    assert len(result["imported"]) == 1
    assert result["updated"] == []
    assert result["errors"] == []

    with sync_db() as db:
        profiles = db.execute(select(Profile)).scalars().all()
        assert len(profiles) == 1
        assert profiles[0].profile_name == "Demo OS"
        assert profiles[0].profile_family == "custom"
        assert Path(profiles[0].package_path).exists()


def test_sync_profiles_catalog_imports_service_custom_packages(tmp_path: Path, sync_db) -> None:
    mount_root = tmp_path / "profiles"
    storage_root = tmp_path / "storage"
    package_dir = mount_root / "Services" / "Custom_AI"
    package_dir.mkdir(parents=True)
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
                "tech_name": "Custom Svc",
                "label": "Custom internal",
                "version": "1.0.0",
                "overview": "Custom internal profile",
                "profile_family": "custom",
                "os": {"name": "Linux", "vendor": "Test", "version": ""},
                "software": {"name": "Custom internal", "vendor": "Test", "category": "Services"},
                "profile_rules": "profile_rules.json",
            }
        ),
        encoding="utf-8",
    )

    settings = SecAuditSettings(
        profiles_path=str(mount_root),
        profiles_storage_path=str(storage_root),
    )

    with sync_db() as db:
        result = sync_profiles_catalog(db, settings)
        db.commit()

    assert result["count"] == 1
    assert len(result["imported"]) == 1

    with sync_db() as db:
        profile = db.execute(select(Profile)).scalar_one()
        assert profile.profile_name == "Custom Svc"
        assert profile.profile_family == "custom"


def test_sync_profiles_catalog_updates_newer_version(tmp_path: Path, sync_db) -> None:
    mount_root = tmp_path / "profiles"
    storage_root = tmp_path / "storage"
    package_v1 = mount_root / "Linux Platform" / "Demo_CRE_AI"
    _write_minimal_package(package_v1, profile_name="Demo OS", version="1.0.0")

    settings = SecAuditSettings(
        profiles_path=str(mount_root),
        profiles_storage_path=str(storage_root),
    )

    with sync_db() as db:
        first = sync_profiles_catalog(db, settings, update_existing=True)
        db.commit()
    assert first["count"] == 1
    assert first["imported"] == [str(package_v1)]

    package_v2 = mount_root / "Linux Platform" / "Demo_CRE_AI_v2"
    _write_minimal_package(package_v2, profile_name="Demo OS", version="2.0.0")

    with sync_db() as db:
        second = sync_profiles_catalog(db, settings, update_existing=True)
        db.commit()

    assert second["count"] == 1
    assert len(second["updated"]) == 1

    with sync_db() as db:
        profile = db.execute(select(Profile).where(Profile.profile_name == "Demo OS")).scalar_one()
        assert profile.version == "2.0.0"


def test_sync_profiles_catalog_refreshes_renamed_scripts_same_version(tmp_path: Path, sync_db) -> None:
    """Same package version but renamed audit script/playbook must re-import on sync."""
    from secaudit_core.models import CheckScript

    mount_root = tmp_path / "profiles"
    storage_root = tmp_path / "storage"
    package_dir = mount_root / "Linux Platform" / "Demo_CRE_AI"
    _write_minimal_package(package_dir, profile_name="Demo OS", version="1.0")

    settings = SecAuditSettings(
        profiles_path=str(mount_root),
        profiles_storage_path=str(storage_root),
    )

    with sync_db() as db:
        first = sync_profiles_catalog(db, settings, update_existing=True)
        db.commit()
    assert first["count"] == 1

    with sync_db() as db:
        profile = db.execute(select(Profile).where(Profile.profile_name == "Demo OS")).scalar_one()
        scripts = db.execute(select(CheckScript).where(CheckScript.profile_id == profile.id)).scalars().all()
        assert [item.script_file for item in scripts] == ["audit.sh"]

    # Rename audit script + update rules binding (same description version).
    old_script = package_dir / "audit.sh"
    new_script = package_dir / "DemoOS.sh"
    old_script.rename(new_script)
    rules = json.loads((package_dir / "profile_rules.json").read_text(encoding="utf-8"))
    rules["rules"][0]["check_script"] = "DemoOS"
    (package_dir / "profile_rules.json").write_text(json.dumps(rules), encoding="utf-8")
    if (package_dir / "demo_compliance.yml").exists():
        pass

    with sync_db() as db:
        second = sync_profiles_catalog(db, settings, update_existing=True)
        db.commit()

    assert second["count"] == 1
    assert len(second["updated"]) == 1
    assert second["skipped"] == []

    with sync_db() as db:
        profile = db.execute(select(Profile).where(Profile.profile_name == "Demo OS")).scalar_one()
        assert profile.version == "1.0"
        scripts = db.execute(select(CheckScript).where(CheckScript.profile_id == profile.id)).scalars().all()
        assert [item.script_file for item in scripts] == ["DemoOS.sh"]
        assert [item.name for item in scripts] == ["DemoOS"]
        assert (Path(profile.package_path) / "DemoOS.sh").is_file()
        assert not (Path(profile.package_path) / "audit.sh").exists()
