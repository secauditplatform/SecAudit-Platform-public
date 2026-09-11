from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch

from secaudit_core.enums import JobStatus, OutboxStatus
from secaudit_core.models import JobRun, TaskOutbox
from secaudit_core.task_outbox import OUTBOX_REDELIVERY_NOTE, reconcile_stuck_outbox_dispatches


def test_reconcile_stuck_outbox_dispatches_resets_sent_pending_callback():
    sent_at = datetime.now(UTC) - timedelta(minutes=5)
    row = TaskOutbox(
        id=470,
        task_name="app.tasks.run_compliance_job",
        args_json="[130]",
        kwargs_json="{}",
        queue="compliance",
        status=OutboxStatus.SENT,
        callback_kind="job_run",
        callback_ref_id=130,
        celery_task_id="secaudit-outbox-470",
        attempts=1,
        sent_at=sent_at,
    )
    job_run = JobRun(id=130, job_id=82, status=JobStatus.PENDING)

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [row]
    db = MagicMock()
    db.execute.return_value = mock_result
    db.get.return_value = job_run

    reset_ids = reconcile_stuck_outbox_dispatches(db, grace=timedelta(minutes=2))

    assert reset_ids == [470]
    assert row.status == OutboxStatus.PENDING
    assert row.sent_at is None
    assert row.last_error == OUTBOX_REDELIVERY_NOTE


def test_reconcile_skips_when_callback_no_longer_pending():
    sent_at = datetime.now(UTC) - timedelta(minutes=5)
    row = TaskOutbox(
        id=471,
        task_name="app.tasks.run_compliance_job",
        args_json="[131]",
        kwargs_json="{}",
        queue="compliance",
        status=OutboxStatus.SENT,
        callback_kind="job_run",
        callback_ref_id=131,
        celery_task_id="secaudit-outbox-471",
        attempts=1,
        sent_at=sent_at,
    )
    job_run = JobRun(id=131, job_id=82, status=JobStatus.RUNNING)

    mock_result = MagicMock()
    mock_result.scalars.return_value.all.return_value = [row]
    db = MagicMock()
    db.execute.return_value = mock_result
    db.get.return_value = job_run

    with patch("secaudit_core.task_outbox._callback_is_dispatchable", return_value=False):
        reset_ids = reconcile_stuck_outbox_dispatches(db, grace=timedelta(minutes=2))

    assert reset_ids == []
    assert row.status == OutboxStatus.SENT
