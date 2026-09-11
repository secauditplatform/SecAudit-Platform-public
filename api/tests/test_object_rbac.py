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


def test_applies_engineer_scope_is_disabled():
    assert applies_engineer_scope([UserRole.OPERATOR.value]) is False
    assert applies_engineer_scope([UserRole.ADMIN.value]) is False
    assert applies_engineer_scope([UserRole.AUDITOR.value]) is False
    assert applies_engineer_scope([UserRole.OPERATOR.value], enabled=False) is False


def test_can_access_owned_resource_allows_all_roles():
    for roles in (
        [UserRole.OPERATOR.value],
        [UserRole.ADMIN.value],
        [UserRole.AUDITOR.value],
    ):
        assert can_access_owned_resource(roles, "local:alice", "local:alice") is True
        assert can_access_owned_resource(roles, "local:alice", "local:bob") is True
        assert can_access_owned_resource(roles, "local:alice", None) is True


def test_assign_host_target_scope_never_enforces_owner_scope():
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

    assert operator_job.enforce_host_owner_scope is False
    assert admin_job.enforce_host_owner_scope is False


@pytest.mark.asyncio
async def test_list_hosts_does_not_apply_owner_filter(monkeypatch):
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
    assert "hosts.owner_sub =" not in captured["sql"]
    assert "hosts.owner_sub==" not in captured["sql"]


from datetime import datetime, timezone

@pytest.mark.asyncio
async def test_get_host_allows_cross_owner_for_operator():
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
    result = await hosts.get_host(
        host_id=1,
        db=fake_db,
        user=AuthUser(sub="local:alice", username="alice", roles=[UserRole.OPERATOR.value]),
    )
    assert result.id == 1


@pytest.mark.asyncio
async def test_list_jobs_does_not_apply_owner_filter(monkeypatch):
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
    assert "jobs.owner_sub =" not in captured["sql"]
    assert "jobs.owner_sub==" not in captured["sql"]


@pytest.mark.asyncio
async def test_assert_hosts_accessible_allows_foreign_host_for_operator():
    foreign = Host(id=5, name="other", hostname="1.1.1.1", port=22, is_active=True, owner_sub="local:bob")
    fake_db = AsyncMock()
    fake_db.get = AsyncMock(return_value=foreign)
    await object_rbac_service.assert_hosts_accessible(
        fake_db,
        AuthUser(sub="local:alice", username="alice", roles=[UserRole.OPERATOR.value]),
        [5],
    )
