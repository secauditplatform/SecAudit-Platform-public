"""Async helpers for transactional task outbox dispatch."""

from __future__ import annotations

import asyncio
import json

from sqlalchemy import create_engine, update
from sqlalchemy.orm import sessionmaker

from secaudit_core.enums import OutboxStatus
from secaudit_core.enums import JobStatus
from secaudit_core.models import JobRun, RemediationRun, TaskOutbox
from secaudit_core.task_outbox import (
    build_outbox_kwargs,
    deterministic_task_id,
    try_dispatch_outbox_by_id,
)


async def enqueue_task_outbox(
    db,
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
    await db.flush()
    row.celery_task_id = deterministic_task_id(row.id)
    model = {
        "job_run": JobRun,
        "remediation_run": RemediationRun,
    }.get(callback_kind)
    if model is not None and callback_ref_id:
        await db.execute(
            update(model)
            .where(
                model.id == callback_ref_id,
                model.status == JobStatus.PENDING,
            )
            .values(celery_task_id=row.celery_task_id)
        )
    await db.refresh(row)
    return row


async def try_dispatch_outbox_immediate(
    outbox_id: int,
    *,
    broker_url: str,
    database_url: str,
    metrics_redis_url: str | None = None,
) -> bool:
    def _run() -> bool:
        engine = create_engine(database_url)
        SessionLocal = sessionmaker(bind=engine)
        with SessionLocal() as session:
            ok = try_dispatch_outbox_by_id(
                session,
                outbox_id,
                broker_url=broker_url,
                metrics_redis_url=metrics_redis_url,
            )
            session.commit()
            return ok

    return await asyncio.to_thread(_run)
