from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from sqlalchemy.sql.dml import Delete

from app.models import CheckResult, Host, JobRun
from app.services import audit_flow


class _Result:
    def __init__(self, rows=(), scalars=()):
        self._rows = list(rows)
        self._scalars = list(scalars)

    def all(self):
        return self._rows

    def scalars(self):
        return SimpleNamespace(all=lambda: self._scalars)


@pytest.mark.asyncio
async def test_delete_run_artifacts_removes_checks_before_ephemeral_host(monkeypatch):
    host_row = SimpleNamespace(
        job_run_id=44,
        extra_runs_json=[{"job_run_id": 45, "profile_id": 2}],
        ephemeral_host_id=7,
        ephemeral_credential_id=9,
        skip_reason="playbook_failed",
    )
    run = SimpleNamespace(id=5, hosts=[host_row])
    monkeypatch.setattr(audit_flow, "load_run", AsyncMock(return_value=run))

    ephemeral = Host(id=7, name="af", hostname="10.0.0.5", port=22, is_ephemeral=True)
    cred = SimpleNamespace(id=9)
    deleted: list[object] = []
    statements: list[object] = []

    async def execute(stmt):
        statements.append(stmt)
        compiled = str(stmt)
        if "job_runs.job_id" in compiled and "job_runs.id" in compiled:
            return _Result(rows=[(12,)])
        if "FROM job_runs" in compiled or "job_runs.job_id" in compiled:
            return _Result(rows=[])
        if "is_ephemeral" in compiled:
            return _Result(scalars=[7])
        if "credential_id" in compiled:
            return _Result(rows=[])
        return _Result()

    db = SimpleNamespace(
        execute=AsyncMock(side_effect=execute),
        flush=AsyncMock(),
        get=AsyncMock(side_effect=lambda model, pk: ephemeral if model is Host else cred),
        delete=AsyncMock(side_effect=lambda obj: deleted.append(obj)),
    )

    await audit_flow.delete_run_artifacts(db, SimpleNamespace(id=5))

    assert host_row.job_run_id is None
    assert host_row.ephemeral_host_id is None
    deletes = [stmt for stmt in statements if isinstance(stmt, Delete)]
    tables = [stmt.table.name for stmt in deletes]
    assert tables.index(CheckResult.__table__.name) < tables.index(JobRun.__table__.name) or CheckResult.__table__.name in tables
    assert CheckResult.__table__.name in tables
    assert JobRun.__table__.name in tables
    assert deleted[0] is ephemeral
    assert cred in deleted
