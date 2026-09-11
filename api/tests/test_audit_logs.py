from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from app.api.v1.routers import audit_logs, jobs
from app.core.auth import AuthUser, require_roles
from app.models import Host, Job, JobScope, UserRole
from secaudit_core.models import AuditLog, TaskOutbox
from app.schemas import JobCreate
from app.services import audit_log as audit_log_service


@pytest.mark.asyncio
async def test_log_audit_event_uses_request_session(monkeypatch):
    class _Db:
        def __init__(self):
            self.saved = []
            self.flushed = False

        def add(self, obj):
            self.saved.append(obj)

        async def flush(self):
            self.flushed = True
            for index, row in enumerate(self.saved, start=1):
                if row.id is None:
                    row.id = index

    db = _Db()
    request = type("Req", (), {"headers": {"user-agent": "pytest"}, "client": None})()
    await audit_log_service.log_audit_event(
        db,
        request,
        AuthUser(sub="local:alice", username="alice", roles=[UserRole.OPERATOR.value], auth_mode="local"),
        action="job.create",
        resource_type="job",
        metadata={"origin": "test"},
    )
    assert db.flushed is True
    assert len(db.saved) == 2
    event = next(row for row in db.saved if isinstance(row, AuditLog))
    assert any(isinstance(row, TaskOutbox) for row in db.saved)
    assert event.actor_username == "alice"
    assert event.metadata_json["auth_mode"] == "local"
    assert event.metadata_json["origin"] == "test"


@pytest.mark.asyncio
async def test_log_audit_event_commits_with_local_user_context(monkeypatch):
    class _AuditSession:
        def __init__(self):
            self.saved = []
            self.committed = False

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        def add(self, obj):
            self.saved.append(obj)

        async def flush(self):
            for index, row in enumerate(self.saved, start=1):
                if row.id is None:
                    row.id = index

        async def commit(self):
            self.committed = True

    session = _AuditSession()
    monkeypatch.setattr(audit_log_service, "async_session", lambda: session)

    request = type("Req", (), {"headers": {"user-agent": "pytest"}, "client": None})()
    await audit_log_service.log_audit_event(
        None,
        request,
        AuthUser(sub="local:alice", username="alice", roles=[UserRole.OPERATOR.value], auth_mode="local"),
        action="job.create",
        resource_type="job",
        metadata={"origin": "test"},
    )
    assert session.committed is True
    assert len(session.saved) == 2
    event = next(row for row in session.saved if isinstance(row, AuditLog))
    assert event.actor_username == "alice"
    assert event.metadata_json["auth_mode"] == "local"
    assert event.metadata_json["origin"] == "test"


@pytest.mark.asyncio
async def test_log_audit_event_supports_sso_user_without_username(monkeypatch):
    class _AuditSession:
        def __init__(self):
            self.saved = []

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, tb):
            return False

        def add(self, obj):
            self.saved.append(obj)

        async def flush(self):
            for index, row in enumerate(self.saved, start=1):
                if row.id is None:
                    row.id = index

        async def commit(self):
            return None

    session = _AuditSession()
    monkeypatch.setattr(audit_log_service, "async_session", lambda: session)
    request = type("Req", (), {"headers": {}, "client": None})()

    await audit_log_service.log_audit_event(
        None,
        request,
        AuthUser(sub="kc:42", username="", roles=[UserRole.AUDITOR.value], auth_mode="sso"),
        action="credential.metadata.view",
        resource_type="credential",
    )
    event = next(row for row in session.saved if isinstance(row, AuditLog))
    assert event.actor_username == "kc:42"
    assert event.metadata_json["auth_mode"] == "sso"


@pytest.mark.asyncio
async def test_audit_log_list_filters_build_query(monkeypatch):
    fake_db = AsyncMock()
    captured = {}

    async def _fake_paginate(_db, stmt, *, offset, limit):
        captured["sql"] = str(stmt)
        return [], 0

    monkeypatch.setattr(audit_logs, "paginate_scalars", _fake_paginate)
    response = await audit_logs.list_audit_logs(
        db=fake_db,
        _=AuthUser(sub="u:1", username="auditor", roles=[UserRole.AUDITOR.value]),
        page=(0, 50),
        action="job.create",
        resource_type="job",
        actor_username="alice",
        outcome="success",
        from_datetime=None,
        to_datetime=None,
    )
    assert response.total == 0
    assert "audit_logs.action" in captured["sql"]
    assert "audit_logs.actor_username" in captured["sql"]


@pytest.mark.asyncio
async def test_audit_overview_timeline_query_uses_single_day_bucket(monkeypatch):
    fake_db = AsyncMock()
    captured: list[str] = []

    async def _execute(stmt):
        captured.append(str(stmt))
        return type("Result", (), {"all": lambda self: [], "scalar_one": lambda self: 0})()

    fake_db.execute = _execute
    response = await audit_logs.get_audit_overview(
        db=fake_db,
        _=AuthUser(sub="u:1", username="auditor", roles=[UserRole.AUDITOR.value]),
        days=14,
        top=5,
    )
    assert response.total_events == 0
    timeline_sql = next(sql for sql in captured if "date_trunc" in sql)
    assert "ORDER BY day" in timeline_sql


@pytest.mark.asyncio
async def test_audit_log_list_authz_checker():
    checker = require_roles(UserRole.AUDITOR, UserRole.OPERATOR, UserRole.ADMIN)
    with pytest.raises(Exception):
        await checker(AuthUser(sub="u:1", username="viewer", roles=[UserRole.OPERATOR.value]))
    allowed = await checker(AuthUser(sub="u:1", username="auditor", roles=[UserRole.AUDITOR.value]))
    assert allowed.username == "auditor"


@pytest.mark.asyncio
async def test_create_job_calls_audit_log(monkeypatch):
    host = Host(id=10, name="h1", hostname="10.0.0.1", port=22, is_active=True)
    created_job = Job(id=7, name="My job")
    created_job.scope = JobScope.STANDARD
    created_job.is_scheduled = False
    created_job.is_active = True
    created_job.created_at = datetime.now(UTC)
    created_job.job_hosts = []

    def _query_result(*, scalar_one=None, scalar_one_or_none_val=None, scalars_all=None):
        class _Scalars:
            def all(self):
                return scalars_all if scalars_all is not None else []

        class _Result:
            def scalar_one(self):
                return scalar_one

            def scalar_one_or_none(self):
                return scalar_one_or_none_val

            def scalars(self):
                return _Scalars()

        return _Result()

    class _Db:
        def add(self, _obj):
            return None

        async def flush(self):
            return None

        async def get(self, model, host_id):
            if model is Host and host_id == 10:
                return host
            return None

        async def execute(self, stmt):
            sql = str(stmt).lower()
            if "profiles" in sql:
                return _query_result(scalar_one_or_none_val=None)
            if "hosts" in sql:
                return _query_result(scalars_all=[host])
            return _query_result(scalar_one=created_job)

    db = _Db()
    logged = AsyncMock()
    monkeypatch.setattr(jobs, "log_audit_event", logged)

    payload = JobCreate(name="My job", profile_id=1, execution_type="ssh", host_ids=[10])
    await jobs.create_job(
        data=payload,
        request=type("Req", (), {"headers": {}, "client": None})(),
        db=db,
        user=AuthUser(sub="u:1", username="builder", roles=[UserRole.OPERATOR.value], auth_mode="local"),
    )
    assert logged.await_count == 1
