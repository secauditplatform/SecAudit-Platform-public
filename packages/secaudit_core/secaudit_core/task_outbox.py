"""Transactional outbox for Celery task dispatch."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session

from secaudit_core.celery_dispatch import send_task
from secaudit_core.celery_observability import (
    CORRELATION_KWARG_KEY,
    record_outbox_dispatch_failure,
    record_outbox_dispatch_lag,
)
from secaudit_core.enums import AuditFlowStatus, JobStatus, OutboxStatus
from secaudit_core.models import AuditFlowRun, InventoryScan, JobRun, RemediationRun, TaskOutbox

MAX_OUTBOX_ATTEMPTS = 5
OUTBOX_DISPATCH_LEASE = timedelta(minutes=5)
OUTBOX_REDELIVERY_GRACE = timedelta(minutes=2)
OUTBOX_REDELIVERY_NOTE = "Redispatching: worker did not claim callback run"


def deterministic_task_id(outbox_id: int) -> str:
    return f"secaudit-outbox-{outbox_id}"


def build_outbox_kwargs(kwargs: dict | None, *, correlation: dict | None = None) -> dict:
    merged = dict(kwargs or {})
    if correlation:
        merged[CORRELATION_KWARG_KEY] = correlation
    return merged


def enqueue_outbox_row(
    db: Session,
    *,
    task_name: str,
    args: list,
    kwargs: dict | None = None,
    queue: str,
    callback_kind: str | None = None,
    callback_ref_id: int | None = None,
    correlation: dict | None = None,
) -> TaskOutbox:
    row = TaskOutbox(
        task_name=task_name,
        args_json=json.dumps(args),
        kwargs_json=json.dumps(build_outbox_kwargs(kwargs, correlation=correlation)),
        queue=queue,
        status=OutboxStatus.PENDING,
        callback_kind=callback_kind,
        callback_ref_id=callback_ref_id,
    )
    db.add(row)
    db.flush()
    row.celery_task_id = deterministic_task_id(row.id)
    _apply_dispatch_success(db, row, row.celery_task_id)
    return row


def _mark_dispatch_failed(db: Session, row: TaskOutbox, exc: Exception) -> None:
    message = str(exc)[:2000]
    model = {
        "job_run": JobRun,
        "remediation_run": RemediationRun,
        "inventory_scan": InventoryScan,
        "audit_flow_run": AuditFlowRun,
    }.get(row.callback_kind)
    if model is not None and row.callback_ref_id:
        failed_status = AuditFlowStatus.FAILED if model is AuditFlowRun else JobStatus.FAILED
        pending_status = AuditFlowStatus.PENDING if model is AuditFlowRun else JobStatus.PENDING
        db.execute(
            update(model)
            .where(
                model.id == row.callback_ref_id,
                model.status == pending_status,
            )
            .values(
                status=failed_status,
                finished_at=datetime.now(UTC),
                error_message=message,
            )
        )


def _apply_dispatch_success(db: Session, row: TaskOutbox, celery_task_id: str) -> None:
    if row.callback_kind == "job_run" and row.callback_ref_id:
        db.execute(
            update(JobRun)
            .where(
                JobRun.id == row.callback_ref_id,
                JobRun.status == JobStatus.PENDING,
            )
            .values(celery_task_id=celery_task_id)
        )
    elif row.callback_kind == "remediation_run" and row.callback_ref_id:
        db.execute(
            update(RemediationRun)
            .where(
                RemediationRun.id == row.callback_ref_id,
                RemediationRun.status == JobStatus.PENDING,
            )
            .values(celery_task_id=celery_task_id)
        )


def _callback_is_dispatchable(db: Session, row: TaskOutbox) -> bool:
    model = {
        "job_run": JobRun,
        "remediation_run": RemediationRun,
        "inventory_scan": InventoryScan,
        "audit_flow_run": AuditFlowRun,
    }.get(row.callback_kind)
    if model is None or not row.callback_ref_id:
        return True
    callback = db.get(model, row.callback_ref_id)
    if callback is None:
        return False
    pending = AuditFlowStatus.PENDING if model is AuditFlowRun else JobStatus.PENDING
    return callback.status == pending


def _claim_outbox_by_id(
    db: Session,
    outbox_id: int,
    *,
    now: datetime | None = None,
) -> TaskOutbox | None:
    now = now or datetime.now(UTC)
    lease_cutoff = now - OUTBOX_DISPATCH_LEASE
    row = db.execute(
        select(TaskOutbox)
        .where(
            TaskOutbox.id == outbox_id,
            or_(
                TaskOutbox.status == OutboxStatus.PENDING,
                (
                    (TaskOutbox.status == OutboxStatus.DISPATCHING)
                    & (TaskOutbox.dispatch_started_at < lease_cutoff)
                ),
            ),
        )
        .with_for_update(skip_locked=True)
    ).scalar_one_or_none()
    if row is None:
        return None
    if not _callback_is_dispatchable(db, row):
        row.status = OutboxStatus.CANCELLED
        row.last_error = "Callback run is missing or no longer PENDING"
        row.dispatch_started_at = None
        db.commit()
        return None
    row.status = OutboxStatus.DISPATCHING
    row.dispatch_started_at = now
    row.attempts += 1
    row.celery_task_id = row.celery_task_id or deterministic_task_id(row.id)
    db.commit()
    return row


def dispatch_outbox_row(
    db: Session,
    row: TaskOutbox,
    *,
    broker_url: str,
    metrics_redis_url: str | None = None,
) -> bool:
    if row.status not in (OutboxStatus.PENDING, OutboxStatus.DISPATCHING):
        return row.status == OutboxStatus.SENT
    if row.status == OutboxStatus.PENDING:
        row.status = OutboxStatus.DISPATCHING
        row.dispatch_started_at = datetime.now(UTC)
        row.attempts += 1
    task_id = row.celery_task_id or deterministic_task_id(row.id)
    row.celery_task_id = task_id
    metrics_url = metrics_redis_url or broker_url

    try:
        args = json.loads(row.args_json)
        kwargs = json.loads(row.kwargs_json or "{}")
        send_task(
            row.task_name,
            args,
            broker_url=broker_url,
            kwargs=kwargs,
            queue=row.queue,
            task_id=task_id,
        )
        # Keep the supplied deterministic id even with nonstandard test/fake
        # brokers that return a different value.
        row.celery_task_id = task_id
        row.status = OutboxStatus.SENT
        row.sent_at = datetime.now(UTC)
        row.dispatch_started_at = None
        row.last_error = None
        if row.created_at is not None:
            created = row.created_at
            if created.tzinfo is None:
                created = created.replace(tzinfo=UTC)
            lag_seconds = (row.sent_at - created).total_seconds()
            record_outbox_dispatch_lag(metrics_url, lag_seconds)
        _apply_dispatch_success(db, row, row.celery_task_id)
        return True
    except Exception as exc:
        row.last_error = str(exc)[:2000]
        record_outbox_dispatch_failure(metrics_url)
        if row.attempts >= MAX_OUTBOX_ATTEMPTS:
            row.status = OutboxStatus.FAILED
            _mark_dispatch_failed(db, row, exc)
        else:
            # A publisher exception can be ambiguous: the broker may have
            # accepted the message. Retry with the same task id; worker claims
            # make any duplicate delivery harmless.
            row.status = OutboxStatus.PENDING
        row.dispatch_started_at = None
        return False


def reconcile_stuck_outbox_dispatches(
    db: Session,
    *,
    grace: timedelta | None = None,
) -> list[int]:
    """Reset SENT outbox rows whose callback is still PENDING for redispatch.

    Covers broker split-brain (API on standalone Redis, worker on Sentinel) where
    tasks were published to a queue no consumer reads.
    """
    cutoff = datetime.now(UTC) - (grace or OUTBOX_REDELIVERY_GRACE)
    rows = db.execute(
        select(TaskOutbox)
        .where(
            TaskOutbox.status == OutboxStatus.SENT,
            TaskOutbox.sent_at.isnot(None),
            TaskOutbox.sent_at < cutoff,
            TaskOutbox.callback_kind.in_(("job_run", "remediation_run", "inventory_scan", "audit_flow_run")),
        )
        .with_for_update(skip_locked=True)
    ).scalars().all()

    reset_ids: list[int] = []
    for row in rows:
        if not _callback_is_dispatchable(db, row):
            continue
        row.status = OutboxStatus.PENDING
        row.sent_at = None
        row.dispatch_started_at = None
        row.last_error = OUTBOX_REDELIVERY_NOTE
        reset_ids.append(row.id)
    return reset_ids


def process_pending_outbox(
    db: Session,
    *,
    broker_url: str,
    metrics_redis_url: str | None = None,
    limit: int = 50,
) -> dict[str, int]:
    lease_cutoff = datetime.now(UTC) - OUTBOX_DISPATCH_LEASE
    row_ids = (
        db.execute(
            select(TaskOutbox.id)
            .where(
                or_(
                    TaskOutbox.status == OutboxStatus.PENDING,
                    (
                        (TaskOutbox.status == OutboxStatus.DISPATCHING)
                        & (TaskOutbox.dispatch_started_at < lease_cutoff)
                    ),
                )
            )
            .order_by(TaskOutbox.created_at)
            .limit(limit)
        )
        .scalars()
        .all()
    )
    sent = 0
    failed = 0
    processed = 0
    for row_id in row_ids:
        row = _claim_outbox_by_id(db, row_id)
        if row is None:
            continue
        processed += 1
        if dispatch_outbox_row(
            db,
            row,
            broker_url=broker_url,
            metrics_redis_url=metrics_redis_url,
        ):
            sent += 1
        elif row.status == OutboxStatus.FAILED:
            failed += 1
        db.commit()
    return {"processed": processed, "sent": sent, "failed": failed}


def process_outbox_cycle(
    db: Session,
    *,
    broker_url: str,
    metrics_redis_url: str | None = None,
    limit: int = 50,
    redelivery_grace: timedelta | None = None,
) -> dict[str, int]:
    """Reconcile stuck dispatches, then publish pending outbox rows."""
    redelivered = reconcile_stuck_outbox_dispatches(db, grace=redelivery_grace)
    result = process_pending_outbox(
        db,
        broker_url=broker_url,
        metrics_redis_url=metrics_redis_url,
        limit=limit,
    )
    result["redelivered"] = len(redelivered)
    return result


def try_dispatch_outbox_by_id(
    db: Session,
    outbox_id: int,
    *,
    broker_url: str,
    metrics_redis_url: str | None = None,
) -> bool:
    row = _claim_outbox_by_id(db, outbox_id)
    if row is None:
        return False
    result = dispatch_outbox_row(
        db,
        row,
        broker_url=broker_url,
        metrics_redis_url=metrics_redis_url,
    )
    db.commit()
    return result
