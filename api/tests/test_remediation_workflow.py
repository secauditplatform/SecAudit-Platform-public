"""Tests for audit → remediation workflow API."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from app.services import remediation_workflow as workflow_service
from app.core.auth import AuthUser
from app.models import CheckResult, CheckStatus, CheckScript, ExecutionType, Job, JobRun, JobStatus, ScriptKind, UserRole


@pytest.mark.asyncio
async def test_build_remediation_suggestion_requires_completed_run():
    run = JobRun(id=1, job_id=10, status=JobStatus.RUNNING)
    job = Job(id=10, name="audit", profile_id=1, owner_sub="local:alice")
    run.job = job
    fake_db = AsyncMock()

    async def _execute(_stmt):
        return MagicMock(scalar_one_or_none=lambda: run)

    fake_db.execute = _execute

    with patch.object(workflow_service, "assert_job_run_access", AsyncMock()):
        with pytest.raises(HTTPException) as exc:
            await workflow_service.build_remediation_suggestion(
                fake_db,
                AuthUser(sub="local:alice", username="alice", roles=[UserRole.OPERATOR.value]),
                1,
            )
    assert exc.value.status_code == 400


@pytest.mark.asyncio
async def test_build_remediation_suggestion_returns_failed_hosts():
    run = JobRun(id=5, job_id=10, status=JobStatus.COMPLETED)
    profile = MagicMock(profile_name="Demo Linux")
    job = Job(id=10, name="weekly", profile_id=2, owner_sub="local:alice", execution_type=ExecutionType.SSH)
    job.profile = profile
    run.job = job

    failed = CheckResult(
        id=1,
        job_run_id=5,
        host_id=7,
        rule_tech_name="R1",
        status=CheckStatus.FAIL,
        message="bad",
    )
    script = CheckScript(
        id=99,
        profile_id=2,
        name="cis_remediation",
        execution_type=ExecutionType.SSH,
        script_file="cis_remediation.sh",
        script_kind=ScriptKind.REMEDIATION,
    )

    fake_db = AsyncMock()

    async def _execute(stmt):
        sql = str(stmt)
        if "job_runs" in sql:
            return MagicMock(scalar_one_or_none=lambda: run)
        if "check_results" in sql:
            return MagicMock(scalars=lambda: MagicMock(all=lambda: [failed]))
        if "check_scripts" in sql:
            return MagicMock(scalars=lambda: MagicMock(all=lambda: [script]))
        return MagicMock()

    fake_db.execute = _execute

    with patch.object(workflow_service, "assert_job_run_access", AsyncMock()):
        result = await workflow_service.build_remediation_suggestion(
            fake_db,
            AuthUser(sub="local:alice", username="alice", roles=[UserRole.OPERATOR.value]),
            5,
        )

    assert result["failed_count"] == 1
    assert result["host_ids"] == [7]
    assert result["default_remediation_script_id"] == 99
