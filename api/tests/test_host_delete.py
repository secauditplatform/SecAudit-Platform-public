"""Tests for host deletion cleanup and guard rails."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from app.api.v1.routers import hosts
from app.core.auth import AuthUser
from app.models import Host, UserRole


@pytest.mark.asyncio
async def test_delete_host_if_allowed_cleans_references_before_delete(monkeypatch):
    host = Host(id=7, name="h7", hostname="10.0.0.7", port=22, is_active=True, owner_sub="local:admin")
    fake_db = AsyncMock()
    fake_db.get = AsyncMock(return_value=host)
    fake_db.delete = AsyncMock()
    fake_db.flush = AsyncMock()

    monkeypatch.setattr(hosts, "_host_has_active_runs", AsyncMock(return_value=False))
    cleanup = AsyncMock()
    monkeypatch.setattr(hosts, "_cleanup_host_references", cleanup)

    user = AuthUser(sub="local:admin", username="admin", roles=[UserRole.ADMIN.value])
    result = await hosts._delete_host_if_allowed(7, fake_db, user)

    assert result is None
    cleanup.assert_awaited_once_with(fake_db, 7)
    fake_db.delete.assert_awaited_once_with(host)
    fake_db.flush.assert_awaited_once()


@pytest.mark.asyncio
async def test_delete_host_if_allowed_blocks_active_runs(monkeypatch):
    host = Host(id=8, name="h8", hostname="10.0.0.8", port=22, is_active=True, owner_sub="local:admin")
    fake_db = AsyncMock()
    fake_db.get = AsyncMock(return_value=host)

    monkeypatch.setattr(hosts, "_host_has_active_runs", AsyncMock(return_value=True))
    cleanup = AsyncMock()
    monkeypatch.setattr(hosts, "_cleanup_host_references", cleanup)

    user = AuthUser(sub="local:admin", username="admin", roles=[UserRole.ADMIN.value])
    result = await hosts._delete_host_if_allowed(8, fake_db, user)

    assert result == hosts._HOST_ACTIVE_RUN
    cleanup.assert_not_awaited()


@pytest.mark.asyncio
async def test_delete_host_if_allowed_denies_foreign_engineer_host():
    host = Host(id=9, name="h9", hostname="10.0.0.9", port=22, is_active=True, owner_sub="local:bob")
    fake_db = AsyncMock()
    fake_db.get = AsyncMock(return_value=host)

    user = AuthUser(sub="local:alice", username="alice", roles=[UserRole.OPERATOR.value])
    result = await hosts._delete_host_if_allowed(9, fake_db, user)

    assert result == hosts._HOST_NOT_FOUND


@pytest.mark.asyncio
async def test_delete_host_endpoint_returns_json_conflict(monkeypatch):
    host = Host(id=10, name="h10", hostname="10.0.0.10", port=22, is_active=True, owner_sub="local:admin")
    fake_db = AsyncMock()
    fake_db.get = AsyncMock(return_value=host)
    fake_request = MagicMock()
    user = AuthUser(sub="local:admin", username="admin", roles=[UserRole.ADMIN.value])

    monkeypatch.setattr(hosts, "_delete_host_if_allowed", AsyncMock(return_value=hosts._HOST_ACTIVE_RUN))
    log_audit = AsyncMock()
    monkeypatch.setattr(hosts, "log_audit_event", log_audit)

    with pytest.raises(HTTPException) as exc:
        await hosts.delete_host(10, fake_request, fake_db, user)

    assert exc.value.status_code == 409
    assert exc.value.detail == hosts._HOST_ACTIVE_RUN
    log_audit.assert_not_awaited()
