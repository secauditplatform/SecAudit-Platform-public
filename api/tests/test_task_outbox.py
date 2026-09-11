"""Tests for transactional task outbox."""

import json
from unittest.mock import MagicMock, patch

import pytest

from secaudit_core.enums import JobStatus, OutboxStatus
from secaudit_core.models import JobRun, TaskOutbox
from secaudit_core.task_outbox import dispatch_outbox_row, enqueue_outbox_row


def test_enqueue_outbox_row_stores_correlation():
    db = MagicMock()
    row = enqueue_outbox_row(
        db,
        task_name="app.tasks.run_compliance_job",
        args=[42],
        queue="compliance",
        callback_kind="job_run",
        callback_ref_id=42,
        correlation={"request_id": "req-1", "run_id": 42},
    )
    kwargs = json.loads(row.kwargs_json or "{}")
    assert kwargs["_secaudit_correlation"]["request_id"] == "req-1"
    assert row.status == OutboxStatus.PENDING
    db.add.assert_called_once()


def test_dispatch_outbox_row_keeps_job_run_pending_until_worker_claim():
    db = MagicMock()
    row = TaskOutbox(
        id=1,
        task_name="app.tasks.run_compliance_job",
        args_json="[7]",
        kwargs_json="{}",
        queue="compliance",
        status=OutboxStatus.PENDING,
        callback_kind="job_run",
        callback_ref_id=7,
        attempts=0,
    )
    job_run = JobRun(id=7, job_id=1, status=JobStatus.PENDING)
    db.get.return_value = job_run

    with patch("secaudit_core.task_outbox.send_task", return_value="task-xyz"):
        ok = dispatch_outbox_row(db, row, broker_url="redis://localhost:6379/0")

    assert ok is True
    assert row.status == OutboxStatus.SENT
    assert row.celery_task_id == "secaudit-outbox-1"
    assert job_run.status == JobStatus.PENDING
    db.execute.assert_called_once()
