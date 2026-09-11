"""Atomic run-state transitions shared by API and workers."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from secaudit_core.enums import JobStatus

TERMINAL_RUN_STATUSES = frozenset(
    {JobStatus.CANCELLED, JobStatus.FAILED, JobStatus.COMPLETED}
)


def claim_pending_run(db: Session, model: Any, run_id: int) -> bool:
    """Atomically claim a dispatchable run. Redeliveries return False."""
    result = db.execute(
        update(model)
        .where(model.id == run_id, model.status == JobStatus.PENDING)
        .values(status=JobStatus.RUNNING, started_at=datetime.now(UTC))
    )
    db.commit()
    db.expire_all()
    return result.rowcount == 1


def transition_running_run(
    db: Session,
    model: Any,
    run_id: int,
    status: JobStatus,
    *,
    error_message: str | None = None,
) -> bool:
    """Finish RUNNING exactly once without overwriting cancellation/terminal state."""
    if status not in TERMINAL_RUN_STATUSES:
        raise ValueError(f"{status!r} is not terminal")
    values: dict[str, Any] = {
        "status": status,
        "finished_at": datetime.now(UTC),
    }
    if error_message is not None:
        values["error_message"] = error_message[:2000]
    result = db.execute(
        update(model)
        .where(model.id == run_id, model.status == JobStatus.RUNNING)
        .values(**values)
    )
    db.commit()
    db.expire_all()
    return result.rowcount == 1


def current_run_status(db: Session, model: Any, run_id: int) -> JobStatus | None:
    return db.execute(select(model.status).where(model.id == run_id)).scalar_one_or_none()
