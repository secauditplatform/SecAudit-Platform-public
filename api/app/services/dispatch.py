"""Shared outbox dispatch flow for API routers."""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models import JobStatus
from app.services.task_outbox import enqueue_task_outbox, try_dispatch_outbox_immediate
from secaudit_core.models import TaskOutbox


def correlation_from_request(request, *, run_kind: str, run_id: int) -> dict:
    return {
        "request_id": request.headers.get("x-request-id"),
        "run_kind": run_kind,
        "run_id": run_id,
    }


async def enqueue_run_dispatch(
    db: AsyncSession,
    *,
    task_name: str,
    args: list,
    queue: str,
    callback_kind: str,
    callback_ref_id: int,
    correlation: dict | None = None,
    kwargs: dict | None = None,
) -> TaskOutbox:
    return await enqueue_task_outbox(
        db,
        task_name=task_name,
        args=args,
        kwargs=kwargs,
        queue=queue,
        callback_kind=callback_kind,
        callback_ref_id=callback_ref_id,
        correlation=correlation,
    )


async def commit_and_try_dispatch(
    db: AsyncSession,
    *,
    outbox_id: int,
    pending_entity,
) -> None:
    """Commit transaction then attempt immediate outbox dispatch."""
    await db.commit()
    await try_dispatch_outbox_immediate(
        outbox_id,
        broker_url=settings.celery_broker_url,
        database_url=settings.database_url_sync,
        metrics_redis_url=settings.redis_url,
    )
    await db.refresh(pending_entity)


async def cancel_active_run(db: AsyncSession, model, run_id: int) -> bool:
    """Atomically cancel PENDING/RUNNING without overwriting a terminal state."""
    result = await db.execute(
        update(model)
        .where(
            model.id == run_id,
            model.status.in_((JobStatus.PENDING, JobStatus.RUNNING)),
        )
        .values(
            status=JobStatus.CANCELLED,
            finished_at=datetime.now(UTC),
            error_message="Cancelled by user",
        )
        .execution_options(synchronize_session=False)
    )
    return result.rowcount == 1
