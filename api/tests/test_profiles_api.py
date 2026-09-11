"""Tests for profile catalog quality API (filters, versioning, sync, bulk)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.core.auth import create_local_token
from app.models import UserRole
from app.services.profiles import ProfileService
from secaudit_core.models import Base, Category, CategoryType, Profile
from secaudit_core.profiles_catalog import build_catalog_sync, os_slug


def _write_minimal_package(
    package_dir: Path,
    *,
    profile_name: str,
    version: str = "1.0",
    os_name: str = "Linux",
    os_version: str = "9",
) -> None:
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
                "os": {"name": os_name, "vendor": "Test", "version": os_version, "icon": "ic_linux.svg"},
                "software": {"name": profile_name, "vendor": "Test", "category": "OS", "version": version},
                "profile_rules": "profile_rules.json",
            }
        ),
        encoding="utf-8",
    )


@pytest.fixture
def profile_service_db(tmp_path: Path):
    db_path = tmp_path / "profiles_api.db"
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
    yield SessionLocal, tmp_path
    engine.dispose()


def test_os_slug_normalizes_names() -> None:
    assert os_slug("Red Hat Enterprise Linux") == "red-hat-enterprise-linux"
    assert os_slug("Linux") == "linux"


def test_build_catalog_includes_os_metadata(profile_service_db) -> None:
    SessionLocal, tmp_path = profile_service_db
    mount_root = tmp_path / "profiles"
    package_dir = mount_root / "Linux Platform" / "Demo_CRE_AI"
    _write_minimal_package(package_dir, profile_name="Demo OS", os_name="Linux", os_version="9")

    with SessionLocal() as db:
        entries = build_catalog_sync(db, str(mount_root))

    assert len(entries) == 1
    assert entries[0]["os_name"] == "Linux"
    assert entries[0]["os_version"] == "9"


def test_profile_service_list_profiles_filters_by_os_slug() -> None:
    service = ProfileService()
    profiles = [
        SimpleNamespace(id=1, profile_name="A", os_name="Linux"),
        SimpleNamespace(id=2, profile_name="B", os_name="Windows"),
    ]

    async def fake_execute(_query):
        class _Result:
            def scalars(self):
                return self

            def all(self):
                return profiles

        return _Result()

    class _Db:
        async def execute(self, query):
            return await fake_execute(query)

    import asyncio

    filtered = asyncio.run(service.list_profiles(_Db(), os="linux"))
    assert [item.profile_name for item in filtered] == ["A"]


def test_enrich_profile_read_marks_needs_update() -> None:
    service = ProfileService()
    profile = SimpleNamespace(
        id=1,
        profile_name="Demo OS",
        version="1.0.0",
        summary=None,
        category_id=None,
        category=None,
        package_path="/data/demo",
        source_format="custom",
        profile_family="custom",
        scap_profile_id=None,
        profile_title=None,
        benchmark_ref=None,
        os_name="Linux",
        os_version="9",
        os_vendor="Test",
        is_active=True,
        created_at=datetime.now(UTC),
    )
    payload = service.enrich_profile_read(profile, {"Demo OS": "2.0.0"})
    assert payload["package_version"] == "2.0.0"
    assert payload["needs_update"] is True


def test_profiles_list_includes_version_and_needs_update(client: TestClient, engineer_headers: dict[str, str]) -> None:
    profile = SimpleNamespace(
        id=1,
        profile_name="Demo OS",
        version="1.0.0",
        summary=None,
        category_id=1,
        category=SimpleNamespace(name="Linux Platform"),
        package_path="/data/demo",
        source_format="custom",
        profile_family="custom",
        scap_profile_id=None,
        profile_title=None,
        benchmark_ref=None,
        os_name="Linux",
        os_version="9",
        os_vendor="Test",
        is_active=True,
        created_at=datetime.now(UTC),
    )

    with patch("app.api.v1.routers.profiles.profile_service.list_profiles", new=AsyncMock(return_value=[profile])), patch(
        "app.api.v1.routers.profiles.profile_service.catalog_latest_versions",
        new=AsyncMock(return_value={"Demo OS": "2.0.0"}),
    ):
        response = client.get("/api/v1/profiles", headers=engineer_headers)

    assert response.status_code == 200
    data = response.json()
    assert data[0]["version"] == "1.0.0"
    assert data[0]["package_version"] == "2.0.0"
    assert data[0]["needs_update"] is True
    assert data[0]["os_name"] == "Linux"


def test_profiles_list_os_filter_query(client: TestClient, engineer_headers: dict[str, str]) -> None:
    list_mock = AsyncMock(return_value=[])
    with patch("app.api.v1.routers.profiles.profile_service.list_profiles", new=list_mock), patch(
        "app.api.v1.routers.profiles.profile_service.catalog_latest_versions",
        new=AsyncMock(return_value={}),
    ):
        response = client.get("/api/v1/profiles?os=linux&os_name=Linux", headers=engineer_headers)

    assert response.status_code == 200
    list_mock.assert_awaited_once()
    kwargs = list_mock.await_args.kwargs
    assert kwargs["os"] == "linux"
    assert kwargs["os_name"] == "Linux"


def test_profile_sync_endpoint(client: TestClient, engineer_headers: dict[str, str]) -> None:
    updated = SimpleNamespace(
        id=5,
        profile_name="Demo OS",
        version="2.0.0",
        summary=None,
        category_id=1,
        category=SimpleNamespace(name="Linux Platform"),
        package_path="/data/demo",
        source_format="custom",
        profile_family="custom",
        scap_profile_id=None,
        profile_title=None,
        benchmark_ref=None,
        os_name="Linux",
        os_version="9",
        os_vendor="Test",
        is_active=True,
        created_at=datetime.now(UTC),
    )
    existing = SimpleNamespace(id=5, version="1.0", profile_name="Demo")

    with patch(
        "app.api.v1.routers.profiles.profile_service.get_profile",
        new=AsyncMock(side_effect=[existing, updated]),
    ), patch(
        "app.api.v1.routers.profiles.profile_service.sync_profile",
        new=AsyncMock(return_value=updated),
    ), patch(
        "app.api.v1.routers.profiles.profile_service.catalog_latest_versions",
        new=AsyncMock(return_value={"Demo OS": "2.0.0"}),
    ), patch("app.api.v1.routers.profiles.log_audit_event", new=AsyncMock()):
        response = client.post("/api/v1/profiles/5/sync", headers=engineer_headers)

    assert response.status_code == 200
    body = response.json()
    assert body["updated"] is True
    assert body["profile"]["version"] == "2.0.0"


def test_bulk_enable_requires_operator(client: TestClient) -> None:
    auditor_token = create_local_token("auditor", [UserRole.AUDITOR.value])
    response = client.post(
        "/api/v1/profiles/bulk/enable",
        headers={"Authorization": f"Bearer {auditor_token}"},
        json={"profile_ids": [1]},
    )
    assert response.status_code == 403


def test_bulk_sync_returns_partial_failures(client: TestClient, engineer_headers: dict[str, str]) -> None:
    with patch(
        "app.api.v1.routers.profiles.profile_service.bulk_sync",
        new=AsyncMock(
            return_value={
                "succeeded": [1],
                "failed": [{"profile_id": 2, "message": "No catalog source found for profile re-sync"}],
            }
        ),
    ), patch("app.api.v1.routers.profiles.log_audit_event", new=AsyncMock()):
        response = client.post(
            "/api/v1/profiles/bulk/sync",
            headers=engineer_headers,
            json={"profile_ids": [1, 2]},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["succeeded"] == [1]
    assert body["failed"][0]["profile_id"] == 2


def test_sync_profiles_catalog_updates_os_fields(profile_service_db, monkeypatch) -> None:
    from secaudit_core.profiles_sync import sync_profiles_catalog
    from secaudit_core.settings import SecAuditSettings

    SessionLocal, tmp_path = profile_service_db
    mount_root = tmp_path / "profiles"
    storage_root = tmp_path / "storage"
    package_dir = mount_root / "Linux Platform" / "Demo_CRE_AI"
    _write_minimal_package(
        package_dir,
        profile_name="Demo OS",
        version="1.0.0",
        os_name="Linux",
        os_version="9",
    )

    sec_settings = SecAuditSettings(
        profiles_path=str(mount_root),
        profiles_storage_path=str(storage_root),
    )

    with SessionLocal() as db:
        result = sync_profiles_catalog(db, sec_settings)
        db.commit()

    assert result["count"] == 1
    with SessionLocal() as db:
        profile = db.execute(select(Profile).where(Profile.profile_name == "Demo OS")).scalar_one()
        assert profile.os_name == "Linux"
        assert profile.os_version == "9"

    package_v2 = mount_root / "Linux Platform" / "Demo_CRE_AI_v2"
    _write_minimal_package(
        package_v2,
        profile_name="Demo OS",
        version="2.0.0",
        os_name="Linux",
        os_version="10",
    )

    with SessionLocal() as db:
        second = sync_profiles_catalog(db, sec_settings, update_existing=True)
        db.commit()

    assert len(second["updated"]) == 1
    with SessionLocal() as db:
        profile = db.execute(select(Profile).where(Profile.profile_name == "Demo OS")).scalar_one()
        assert profile.version == "2.0.0"
        assert profile.os_version == "10"
