"""Tests for object RBAC on reports and websocket log endpoints."""

from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from app.api.v1.routers import reports, ws
from app.core.auth import AuthUser
from app.models import Job, JobRun, JobStatus, RemediationJob, RemediationRun, UserRole
from app.services import object_rbac as object_rbac_service


class _FakeRedis:
    async def lrange(self, *_args, **_kwargs):
        return []

    async def aclose(self):
        return None


@pytest.mark.asyncio
async def test_assert_job_run_access_allows_cross_owner_for_operator():
    run = JobRun(id=5, job_id=10, status=JobStatus.COMPLETED)
    job = Job(id=10, name="j1", owner_sub="local:bob")
    fake_db = AsyncMock()

    async def _get(model, pk):
        if model.__name__ == "JobRun":
            return run if pk == 5 else None
        if model.__name__ == "Job":
            return job if pk == 10 else None
        return None

    fake_db.get = _get
    result = await object_rbac_service.assert_job_run_access(
        fake_db,
        AuthUser(sub="local:alice", username="alice", roles=[UserRole.OPERATOR.value]),
        5,
    )
    assert result.id == 5


@pytest.mark.asyncio
async def test_assert_remediation_run_access_allows_cross_owner_for_operator():
    run = RemediationRun(id=5, remediation_job_id=10, status=JobStatus.COMPLETED)
    job = RemediationJob(id=10, name="rj1", owner_sub="local:bob")
    fake_db = AsyncMock()

    async def _get(model, pk):
        if model.__name__ == "RemediationRun":
            return run if pk == 5 else None
        if model.__name__ == "RemediationJob":
            return job if pk == 10 else None
        return None

    fake_db.get = _get
    result = await object_rbac_service.assert_remediation_run_access(
        fake_db,
        AuthUser(sub="local:alice", username="alice", roles=[UserRole.OPERATOR.value]),
        5,
    )
    assert result.id == 5


@pytest.mark.asyncio
async def test_get_run_summary_checks_access(monkeypatch):
    async def _assert(*_args, **_kwargs):
        raise HTTPException(status_code=404, detail="Job run not found")

    monkeypatch.setattr(reports, "assert_job_run_access", _assert)
    fake_db = AsyncMock()
    with pytest.raises(HTTPException) as exc:
        await reports.get_run_summary(
            run_id=99,
            db=fake_db,
            user=AuthUser(sub="local:alice", username="alice", roles=[UserRole.OPERATOR.value]),
        )
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_job_run_logs_checks_access(monkeypatch):
    called = {"run_id": None}

    async def _assert(_db, _user, run_id):
        called["run_id"] = run_id

    monkeypatch.setattr(ws, "assert_job_run_access", _assert)
    monkeypatch.setattr(ws, "async_redis", lambda *_a, **_k: _FakeRedis())

    entries = await ws.get_job_run_logs(
        run_id=42,
        db=AsyncMock(),
        user=AuthUser(sub="local:alice", username="alice", roles=[UserRole.OPERATOR.value]),
    )
    assert called["run_id"] == 42
    assert entries == []


@pytest.mark.asyncio
async def test_remediation_run_logs_checks_access(monkeypatch):
    called = {"run_id": None}

    async def _assert(_db, _user, run_id):
        called["run_id"] = run_id

    monkeypatch.setattr(ws, "assert_remediation_run_access", _assert)
    monkeypatch.setattr(ws, "async_redis", lambda *_a, **_k: _FakeRedis())

    entries = await ws.get_remediation_run_logs(
        run_id=7,
        db=AsyncMock(),
        user=AuthUser(sub="local:alice", username="alice", roles=[UserRole.OPERATOR.value]),
    )
    assert called["run_id"] == 7
    assert entries == []
