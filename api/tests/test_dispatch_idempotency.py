"""Focused dispatch, cancellation, and redelivery invariants."""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from secaudit_core.base import Base
from secaudit_core.enums import CheckStatus, JobStatus, OutboxStatus
from secaudit_core.models import (
    CheckResult,
    JobRun,
    RemediationResult,
    RemediationRun,
    TaskOutbox,
)
from secaudit_core.run_state import claim_pending_run, transition_running_run
from secaudit_core.result_upsert import upsert_check_result, upsert_remediation_result
from secaudit_core.task_outbox import (
    OUTBOX_DISPATCH_LEASE,
    _claim_outbox_by_id,
    enqueue_outbox_row,
    process_pending_outbox,
    try_dispatch_outbox_by_id,
)


@pytest.fixture()
def db() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


def _job_run(db: Session, *, status: JobStatus = JobStatus.PENDING) -> JobRun:
    run = JobRun(job_id=1, status=status)
    db.add(run)
    db.commit()
    return run


def test_atomic_worker_claim_makes_redelivery_a_noop(db):
    run = _job_run(db)

    assert claim_pending_run(db, JobRun, run.id) is True
    assert claim_pending_run(db, JobRun, run.id) is False

    db.refresh(run)
    assert run.status == JobStatus.RUNNING
    assert run.started_at is not None


@pytest.mark.parametrize(
    "terminal_status",
    [JobStatus.CANCELLED, JobStatus.FAILED, JobStatus.COMPLETED],
)
def test_terminal_run_cannot_be_claimed(db, terminal_status):
    run = _job_run(db, status=terminal_status)
    assert claim_pending_run(db, JobRun, run.id) is False


def test_completion_cannot_overwrite_cancellation(db):
    run = _job_run(db)
    assert claim_pending_run(db, JobRun, run.id)
    run.status = JobStatus.CANCELLED
    run.finished_at = datetime.now(UTC)
    db.commit()

    assert (
        transition_running_run(db, JobRun, run.id, JobStatus.COMPLETED)
        is False
    )
    db.refresh(run)
    assert run.status == JobStatus.CANCELLED


def test_terminal_callback_cancels_outbox_without_publish(db):
    run = _job_run(db, status=JobStatus.FAILED)
    row = enqueue_outbox_row(
        db,
        task_name="app.tasks.run_compliance_job",
        args=[run.id],
        queue="compliance",
        callback_kind="job_run",
        callback_ref_id=run.id,
    )
    db.commit()

    with patch("secaudit_core.task_outbox.send_task") as publish:
        assert try_dispatch_outbox_by_id(db, row.id, broker_url="memory://") is False

    db.refresh(row)
    assert row.status == OutboxStatus.CANCELLED
    publish.assert_not_called()


def test_ambiguous_publish_retries_with_same_task_id(db):
    run = _job_run(db)
    row = enqueue_outbox_row(
        db,
        task_name="app.tasks.run_compliance_job",
        args=[run.id],
        queue="compliance",
        callback_kind="job_run",
        callback_ref_id=run.id,
    )
    db.commit()
    expected_task_id = f"secaudit-outbox-{row.id}"

    with patch(
        "secaudit_core.task_outbox.send_task",
        side_effect=RuntimeError("publisher confirm timed out"),
    ) as first_publish:
        assert try_dispatch_outbox_by_id(db, row.id, broker_url="memory://") is False
    assert first_publish.call_args.kwargs["task_id"] == expected_task_id
    db.refresh(row)
    assert row.status == OutboxStatus.PENDING
    assert run.status == JobStatus.PENDING

    with patch(
        "secaudit_core.task_outbox.send_task",
        return_value=expected_task_id,
    ) as retry_publish:
        assert try_dispatch_outbox_by_id(db, row.id, broker_url="memory://") is True
    assert retry_publish.call_args.kwargs["task_id"] == expected_task_id
    db.refresh(row)
    db.refresh(run)
    assert row.status == OutboxStatus.SENT
    assert run.status == JobStatus.PENDING
    assert run.celery_task_id == expected_task_id


def test_unexpired_dispatch_claim_blocks_immediate_poller_race(db):
    run = _job_run(db)
    row = enqueue_outbox_row(
        db,
        task_name="app.tasks.run_compliance_job",
        args=[run.id],
        queue="compliance",
        callback_kind="job_run",
        callback_ref_id=run.id,
    )
    db.commit()

    assert _claim_outbox_by_id(db, row.id) is not None
    assert _claim_outbox_by_id(db, row.id) is None


def test_expired_dispatch_lease_is_recovered(db):
    run = _job_run(db)
    row = enqueue_outbox_row(
        db,
        task_name="app.tasks.run_compliance_job",
        args=[run.id],
        queue="compliance",
        callback_kind="job_run",
        callback_ref_id=run.id,
    )
    row.status = OutboxStatus.DISPATCHING
    row.dispatch_started_at = datetime.now(UTC) - OUTBOX_DISPATCH_LEASE - timedelta(seconds=1)
    db.commit()

    with patch(
        "secaudit_core.task_outbox.send_task",
        return_value=row.celery_task_id,
    ):
        result = process_pending_outbox(db, broker_url="memory://")

    assert result == {"processed": 1, "sent": 1, "failed": 0}
    db.refresh(row)
    assert row.status == OutboxStatus.SENT


@pytest.mark.parametrize(
    ("model", "first", "duplicate"),
    [
        (
            CheckResult,
            {
                "job_run_id": 1,
                "host_id": 1,
                "rule_tech_name": "rule-1",
                "status": CheckStatus.PASS,
            },
            {
                "job_run_id": 1,
                "host_id": 1,
                "rule_tech_name": "rule-1",
                "status": CheckStatus.FAIL,
            },
        ),
        (
            RemediationResult,
            {
                "remediation_run_id": 1,
                "host_id": 1,
                "script_name": "fix",
                "status": CheckStatus.PASS,
            },
            {
                "remediation_run_id": 1,
                "host_id": 1,
                "script_name": "fix",
                "status": CheckStatus.ERROR,
            },
        ),
    ],
)
def test_result_uniqueness_rejects_conflicting_duplicates(db, model, first, duplicate):
    db.add(model(**first))
    db.commit()
    db.add(model(**duplicate))
    with pytest.raises(IntegrityError):
        db.commit()


def test_remediation_result_redelivery_upserts_single_row(db):
    values = {
        "remediation_run_id": 9,
        "host_id": 4,
        "script_name": "fix-once",
        "message": "first",
        "raw_output": "first output",
    }
    upsert_remediation_result(db, status=CheckStatus.PASS, **values)
    db.commit()
    upsert_remediation_result(
        db,
        status=CheckStatus.ERROR,
        **{**values, "message": "final", "raw_output": "final output"},
    )
    db.commit()

    rows = db.query(RemediationResult).all()
    assert len(rows) == 1
    assert rows[0].status == CheckStatus.ERROR
    assert rows[0].message == "final"


def test_compliance_result_redelivery_upserts_single_row(db):
    values = {
        "job_run_id": 12,
        "host_id": 8,
        "rule_tech_name": "rule-once",
        "message": "first",
        "raw_output": "first output",
    }
    upsert_check_result(db, status=CheckStatus.PASS, **values)
    db.commit()
    upsert_check_result(
        db,
        status=CheckStatus.FAIL,
        **{**values, "message": "final", "raw_output": "final output"},
    )
    db.commit()

    rows = db.query(CheckResult).all()
    assert len(rows) == 1
    assert rows[0].status == CheckStatus.FAIL
    assert rows[0].message == "final"
