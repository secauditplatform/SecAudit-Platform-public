"""Tests for object-level RBAC helpers."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from app.api.v1.routers import hosts, jobs
from app.core.auth import AuthUser
from app.models import Host, Job, RemediationJob, UserRole
from app.services import object_rbac as object_rbac_service
from secaudit_core.object_rbac import (
    applies_engineer_scope,
    can_access_owned_resource,
)


def test_applies_engineer_scope_scopes_non_admins_when_enabled():
    assert applies_engineer_scope([UserRole.OPERATOR.value]) is True
    assert applies_engineer_scope([UserRole.AUDITOR.value]) is True
    assert applies_engineer_scope([UserRole.ADMIN.value]) is False
    assert applies_engineer_scope([UserRole.OPERATOR.value], enabled=False) is False


def test_can_access_owned_resource_scopes_non_admins():
    assert can_access_owned_resource([UserRole.OPERATOR.value], "local:alice", "local:alice") is True
    assert can_access_owned_resource([UserRole.OPERATOR.value], "local:alice", "local:bob") is False
    assert can_access_owned_resource([UserRole.OPERATOR.value], "local:alice", None) is True
    assert can_access_owned_resource(
        [UserRole.OPERATOR.value], "local:alice", None, mutate=True
    ) is False
    assert can_access_owned_resource([UserRole.ADMIN.value], "local:alice", "local:bob") is True
    assert can_access_owned_resource([UserRole.ADMIN.value], "local:alice", None, mutate=True) is True
    assert can_access_owned_resource([UserRole.AUDITOR.value], "local:alice", "local:bob") is False


def test_assign_host_target_scope_enforces_for_operators(monkeypatch):
    monkeypatch.setattr(object_rbac_service.settings, "object_rbac_enabled", True)
    operator_job = Job()
    admin_job = RemediationJob()

    object_rbac_service.assign_host_target_scope(
        operator_job,
        AuthUser(sub="local:alice", username="alice", roles=[UserRole.OPERATOR.value]),
    )
    object_rbac_service.assign_host_target_scope(
        admin_job,
        AuthUser(sub="local:admin", username="admin", roles=[UserRole.ADMIN.value]),
    )

    assert operator_job.enforce_host_owner_scope is True
    assert admin_job.enforce_host_owner_scope is False


@pytest.mark.asyncio
async def test_list_hosts_applies_owner_filter(monkeypatch):
    monkeypatch.setattr(object_rbac_service.settings, "object_rbac_enabled", True)
    fake_db = AsyncMock()
    captured: dict[str, str] = {}

    async def _fake_paginate(_db, stmt, *, offset, limit):
        captured["sql"] = str(stmt)
        return [], 0

    monkeypatch.setattr(hosts, "paginate_scalars", _fake_paginate)
    await hosts.list_hosts(
        db=fake_db,
        user=AuthUser(sub="local:op1", username="op1", roles=[UserRole.OPERATOR.value]),
        page=(0, 50),
        tag=[],
        active_only=False,
        search=None,
    )
    sql = captured["sql"].replace(" ", "")
    assert "owner_sub" in captured["sql"]
    assert "local:op1" in captured["sql"] or "owner_sub" in sql


@pytest.mark.asyncio
async def test_get_host_denies_cross_owner_for_operator(monkeypatch):
    monkeypatch.setattr(object_rbac_service.settings, "object_rbac_enabled", True)
    host = Host(
        id=1,
        name="h1",
        hostname="10.0.0.1",
        port=22,
        is_active=True,
        owner_sub="local:bob",
        created_at=datetime.now(timezone.utc),
    )
    fake_db = AsyncMock()

    async def _execute(_stmt):
        return type("R", (), {"scalar_one_or_none": lambda self: host})()

    fake_db.execute = _execute
    with pytest.raises(HTTPException) as exc:
        await hosts.get_host(
            host_id=1,
            db=fake_db,
            user=AuthUser(sub="local:alice", username="alice", roles=[UserRole.OPERATOR.value]),
        )
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_list_jobs_applies_owner_filter(monkeypatch):
    monkeypatch.setattr(object_rbac_service.settings, "object_rbac_enabled", True)
    fake_db = AsyncMock()
    captured: dict[str, str] = {}

    async def _execute(stmt):
        captured["sql"] = str(stmt)
        return type("R", (), {"scalars": lambda self: type("S", (), {"all": lambda self: []})()})()

    fake_db.execute = _execute
    await jobs.list_jobs(
        db=fake_db,
        user=AuthUser(sub="local:op1", username="op1", roles=[UserRole.OPERATOR.value]),
    )
    assert "owner_sub" in captured["sql"]


@pytest.mark.asyncio
async def test_assert_hosts_accessible_denies_foreign_host_for_operator(monkeypatch):
    monkeypatch.setattr(object_rbac_service.settings, "object_rbac_enabled", True)
    foreign = Host(id=5, name="other", hostname="1.1.1.1", port=22, is_active=True, owner_sub="local:bob")
    fake_db = AsyncMock()
    fake_db.get = AsyncMock(return_value=foreign)
    with pytest.raises(HTTPException) as exc:
        await object_rbac_service.assert_hosts_accessible(
            fake_db,
            AuthUser(sub="local:alice", username="alice", roles=[UserRole.OPERATOR.value]),
            [5],
        )
    assert exc.value.status_code == 404
