from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

from secaudit_core.celery_reliability import (
    PENDING_ORPHAN_ERROR_MESSAGE,
    STALE_RUN_ERROR_MESSAGE,
    WORKER_LOST_ERROR_MESSAGE,
)
from secaudit_core.models import JobRun, JobStatus, RemediationRun
from secaudit_core.stale_runs import (
    reconcile_worker_lost_runs,
    sweep_orphan_pending_job_runs,
    sweep_stale_job_runs,
    sweep_stale_remediation_runs,
    sweep_stale_runs,
)


def _mock_db_with_runs(runs: list) -> MagicMock:
    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = runs
    mock_db = MagicMock()
    mock_db.execute.return_value = mock_result
    return mock_db


def test_sweep_stale_job_runs_marks_failed():
    started = datetime.now(UTC) - timedelta(hours=3)
    run = JobRun(id=1, job_id=10, status=JobStatus.RUNNING, started_at=started)
    db = _mock_db_with_runs([run])

    affected = sweep_stale_job_runs(db, datetime.now(UTC) - timedelta(hours=2))

    assert affected == [1]
    assert run.status == JobStatus.FAILED
    assert run.error_message == STALE_RUN_ERROR_MESSAGE
    assert run.finished_at is not None


def test_sweep_stale_remediation_runs_marks_failed():
    started = datetime.now(UTC) - timedelta(hours=3)
    run = RemediationRun(id=2, remediation_job_id=5, status=JobStatus.RUNNING, started_at=started)
    db = _mock_db_with_runs([run])

    affected = sweep_stale_remediation_runs(db, datetime.now(UTC) - timedelta(hours=2))

    assert affected == [2]
    assert run.status == JobStatus.FAILED
    assert run.error_message == STALE_RUN_ERROR_MESSAGE


def test_sweep_orphan_pending_job_runs_marks_failed():
    created = datetime.now(UTC) - timedelta(minutes=30)
    run = JobRun(id=3, job_id=10, status=JobStatus.PENDING, created_at=created)
    db = _mock_db_with_runs([run])

    affected = sweep_orphan_pending_job_runs(db, datetime.now(UTC) - timedelta(minutes=5))

    assert affected == [3]
    assert run.status == JobStatus.FAILED
    assert run.error_message == PENDING_ORPHAN_ERROR_MESSAGE
    assert run.finished_at is not None


def test_sweep_stale_runs_returns_both_kinds():
    job_run = JobRun(id=1, job_id=10, status=JobStatus.RUNNING, started_at=datetime.now(UTC))
    remediation_run = RemediationRun(
        id=2, remediation_job_id=5, status=JobStatus.RUNNING, started_at=datetime.now(UTC)
    )
    db = MagicMock()
    db.execute.side_effect = [
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[job_run])))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[remediation_run])))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))),
    ]
    cutoff = datetime.now(UTC) - timedelta(minutes=1)

    result = sweep_stale_runs(db, cutoff)

    assert result == {
        "job_runs": [1],
        "remediation_runs": [2],
        "pending_job_runs": [],
        "pending_remediation_runs": [],
    }


def test_reconcile_worker_lost_runs_marks_orphaned_running_runs_failed():
    started = datetime.now(UTC) - timedelta(minutes=10)
    run = JobRun(
        id=146,
        job_id=87,
        status=JobStatus.RUNNING,
        started_at=started,
        celery_task_id="secaudit-outbox-570",
    )
    db = MagicMock()
    db.execute.side_effect = [
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[run])))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))),
    ]

    affected = reconcile_worker_lost_runs(db, set(), grace=timedelta(minutes=3))

    assert affected == {"job_runs": [146], "remediation_runs": []}
    assert run.status == JobStatus.FAILED
    assert run.error_message == WORKER_LOST_ERROR_MESSAGE


def test_reconcile_worker_lost_runs_keeps_active_tasks():
    started = datetime.now(UTC) - timedelta(minutes=10)
    run = JobRun(
        id=146,
        job_id=87,
        status=JobStatus.RUNNING,
        started_at=started,
        celery_task_id="secaudit-outbox-570",
    )
    db = MagicMock()
    db.execute.side_effect = [
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[run])))),
        MagicMock(scalars=MagicMock(return_value=MagicMock(all=MagicMock(return_value=[])))),
    ]

    affected = reconcile_worker_lost_runs(
        db,
        {"secaudit-outbox-570"},
        grace=timedelta(minutes=3),
    )

    assert affected == {"job_runs": [], "remediation_runs": []}
    assert run.status == JobStatus.RUNNING
