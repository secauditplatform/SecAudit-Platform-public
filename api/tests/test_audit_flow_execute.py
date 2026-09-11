from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from app.models import AuditFlowStatus, JobRun, JobStatus
from app.services.audit_flow import (
    apply_host_selection,
    can_launch_host,
    clear_retryable_skip,
    cleanup_run_ephemeral_credentials,
    prepare_run_for_execute,
    refresh_run_status,
    sweep_orphaned_ephemeral_credentials,
)


def test_can_launch_host_after_auth_failed():
    row = SimpleNamespace(
        selected=True,
        profile_id=3,
        credential_id=8,
        job_run_id=None,
        skip_reason="auth_failed",
    )
    assert can_launch_host(row) is True


def test_can_launch_host_requires_profile_and_credential():
    row = SimpleNamespace(selected=True, profile_id=3, credential_id=None, job_run_id=None)
    assert can_launch_host(row) is False


def test_can_launch_host_skips_already_started():
    row = SimpleNamespace(selected=True, profile_id=3, credential_id=8, job_run_id=11)
    assert can_launch_host(row) is False


def test_prepare_run_for_execute_reopens_completed():
    run = SimpleNamespace(
        status=AuditFlowStatus.COMPLETED,
        finished_at="now",
        error_message=None,
    )
    prepare_run_for_execute(run)
    assert run.status == AuditFlowStatus.READY
    assert run.finished_at is None


def test_prepare_run_for_execute_reopens_cancelled():
    run = SimpleNamespace(
        status=AuditFlowStatus.CANCELLED,
        finished_at="now",
        error_message="Cancelled by user",
    )
    prepare_run_for_execute(run)
    assert run.status == AuditFlowStatus.READY
    assert run.error_message is None


def test_prepare_run_for_execute_rejects_scanning():
    run = SimpleNamespace(status=AuditFlowStatus.SCANNING, finished_at=None, error_message=None)
    with pytest.raises(ValueError, match="ready"):
        prepare_run_for_execute(run)


def test_clear_retryable_skip():
    row = SimpleNamespace(skip_reason="auth_failed", skip_detail="No working credential pair")
    clear_retryable_skip(row)
    assert row.skip_reason is None
    assert row.skip_detail is None


def test_apply_host_selection_marks_skipped_when_deselected():
    row = SimpleNamespace(
        selected=True,
        job_run_id=None,
        skip_reason=None,
        skip_detail=None,
    )
    apply_host_selection(row, False)
    assert row.selected is False
    assert row.skip_reason == "skipped_by_user"
    assert row.skip_detail == "Not selected for compliance"


def test_apply_host_selection_restores_ready_when_reselected():
    row = SimpleNamespace(
        selected=False,
        job_run_id=None,
        skip_reason="skipped_by_user",
        skip_detail="Not selected for compliance",
    )
    apply_host_selection(row, True)
    assert row.selected is True
    assert row.skip_reason is None
    assert row.skip_detail is None


def test_apply_host_selection_keeps_no_matching_profile_on_reselect():
    row = SimpleNamespace(
        selected=False,
        job_run_id=None,
        skip_reason="no_matching_profile",
        skip_detail=None,
    )
    apply_host_selection(row, True)
    assert row.selected is True
    assert row.skip_reason == "no_matching_profile"


@pytest.mark.asyncio
async def test_cleanup_run_ephemeral_credentials_unlinks_then_deletes():
    cred = SimpleNamespace(id=9, is_ephemeral=True, description="AuditFlow ephemeral")
    row = SimpleNamespace(ephemeral_credential_id=9)
    run = SimpleNamespace(hosts=[row])
    deleted: list[object] = []
    db = SimpleNamespace(
        execute=AsyncMock(),
        flush=AsyncMock(),
        get=AsyncMock(return_value=cred),
        delete=AsyncMock(side_effect=lambda obj: deleted.append(obj)),
    )

    await cleanup_run_ephemeral_credentials(db, run)

    assert row.ephemeral_credential_id is None
    db.execute.assert_awaited()
    assert cred in deleted


@pytest.mark.asyncio
async def test_cleanup_skips_durable_catalog_credentials():
    cred = SimpleNamespace(id=9, is_ephemeral=False, description="prod root")
    row = SimpleNamespace(ephemeral_credential_id=9)
    run = SimpleNamespace(hosts=[row])
    deleted: list[object] = []
    db = SimpleNamespace(
        execute=AsyncMock(),
        flush=AsyncMock(),
        get=AsyncMock(return_value=cred),
        delete=AsyncMock(side_effect=lambda obj: deleted.append(obj)),
    )

    await cleanup_run_ephemeral_credentials(db, run)

    assert row.ephemeral_credential_id is None
    assert deleted == []


@pytest.mark.asyncio
async def test_refresh_run_status_deletes_ephemeral_credentials_when_complete():
    cred = SimpleNamespace(id=9, is_ephemeral=True, description="AuditFlow ephemeral")
    row = SimpleNamespace(
        job_run_id=44,
        extra_runs_json=None,
        ephemeral_credential_id=9,
        skip_reason=None,
    )
    run = SimpleNamespace(status=AuditFlowStatus.RUNNING, hosts=[row], finished_at=None)
    job_run = SimpleNamespace(id=44, status=JobStatus.COMPLETED, error_message=None)
    deleted: list[object] = []

    async def getter(model, pk):
        if model is JobRun:
            return job_run
        return cred

    db = SimpleNamespace(
        execute=AsyncMock(),
        flush=AsyncMock(),
        get=AsyncMock(side_effect=getter),
        delete=AsyncMock(side_effect=lambda obj: deleted.append(obj)),
    )

    await refresh_run_status(db, run)

    assert run.status == AuditFlowStatus.COMPLETED
    assert row.ephemeral_credential_id is None
    assert cred in deleted


@pytest.mark.asyncio
async def test_refresh_run_status_keeps_credentials_while_jobs_run():
    row = SimpleNamespace(
        job_run_id=44,
        extra_runs_json=None,
        ephemeral_credential_id=9,
        skip_reason="checking",
    )
    run = SimpleNamespace(status=AuditFlowStatus.RUNNING, hosts=[row], finished_at=None)
    job_run = SimpleNamespace(id=44, status=JobStatus.RUNNING, error_message=None)
    db = SimpleNamespace(
        execute=AsyncMock(),
        flush=AsyncMock(),
        get=AsyncMock(return_value=job_run),
        delete=AsyncMock(),
    )

    await refresh_run_status(db, run)

    assert run.status == AuditFlowStatus.RUNNING
    assert row.ephemeral_credential_id == 9
    db.delete.assert_not_called()


@pytest.mark.asyncio
async def test_sweep_deletes_ephemeral_credentials_not_used_by_active_run():
    cred = SimpleNamespace(id=9, is_ephemeral=True, description="AuditFlow ephemeral")
    deleted: list[object] = []
    calls = {"n": 0}

    async def execute(stmt):
        calls["n"] += 1
        if calls["n"] == 1:
            return SimpleNamespace(scalars=lambda: SimpleNamespace(all=lambda: [cred]))
        return SimpleNamespace(all=lambda: [])

    db = SimpleNamespace(
        execute=AsyncMock(side_effect=execute),
        flush=AsyncMock(),
        get=AsyncMock(return_value=cred),
        delete=AsyncMock(side_effect=lambda obj: deleted.append(obj)),
    )

    await sweep_orphaned_ephemeral_credentials(db)

    assert cred in deleted
