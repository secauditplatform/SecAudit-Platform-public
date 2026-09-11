"""Dead-letter queue persistence and replay for Celery tasks."""

from __future__ import annotations

import json
import logging
import traceback as tb_module
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from secaudit_core.celery_dispatch import send_task
from secaudit_core.celery_observability import CORRELATION_KWARG_KEY
from secaudit_core.enums import DeadLetterStatus
from secaudit_core.models import TaskDeadLetter
from secaudit_core.sensitive_data import redact_sensitive

logger = logging.getLogger(__name__)

DLQ_METRICS_PREFIX = "secaudit:metrics:dlq"
DLQ_REDIS_LIST_PREFIX = "secaudit:dlq"


def dlq_redis_list_key(queue: str) -> str:
    return f"{DLQ_REDIS_LIST_PREFIX}:{queue}"


def _serialize_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)


def _resolve_queue(task_name: str, delivery_info: dict | None) -> str:
    if delivery_info:
        routing_key = delivery_info.get("routing_key")
        if routing_key:
            return str(routing_key)
    if "compliance" in task_name:
        return "compliance"
    if "remediation" in task_name:
        return "remediation"
    if "inventory" in task_name:
        return "inventory"
    return "maintenance"


def record_dead_letter(
    session: Session,
    *,
    celery_task_id: str | None,
    task_name: str,
    queue: str,
    args: list | tuple,
    kwargs: dict | None,
    exc: BaseException,
    traceback_text: str | None,
    retry_count: int,
    redis_url: str | None = None,
) -> TaskDeadLetter:
    safe_kwargs = dict(kwargs or {})
    row = TaskDeadLetter(
        celery_task_id=celery_task_id,
        task_name=task_name,
        queue=queue,
        args_json=_serialize_json(list(args)),
        kwargs_json=_serialize_json(safe_kwargs) if safe_kwargs else None,
        exception_type=type(exc).__name__,
        exception_message=redact_sensitive(str(exc))[:4000],
        traceback_text=(traceback_text or "")[:16000] or None,
        retry_count=retry_count,
        status=DeadLetterStatus.PENDING,
    )
    session.add(row)
    session.commit()
    session.refresh(row)

    if redis_url:
        record_dead_letter_redis(redis_url, queue=queue, dead_letter_id=row.id, task_name=task_name)
    logger.warning(
        "Celery task dead-lettered id=%s task=%s queue=%s retries=%s error=%s",
        row.id,
        task_name,
        queue,
        retry_count,
        row.exception_type,
    )
    return row


def record_dead_letter_redis(
    redis_url: str,
    *,
    queue: str,
    dead_letter_id: int,
    task_name: str,
) -> None:
    from secaudit_core.celery_observability import redis_client

    client = redis_client(redis_url)
    try:
        payload = _serialize_json(
            {
                "id": dead_letter_id,
                "task_name": task_name,
                "queue": queue,
                "recorded_at": datetime.now(UTC).isoformat(),
            }
        )
        client.lpush(dlq_redis_list_key(queue), payload)
        client.hincrby(f"{DLQ_METRICS_PREFIX}:dead_lettered_total", queue, 1)
    finally:
        client.close()


def fetch_dlq_stats(database_url: str) -> dict[str, float]:
    from secaudit_core.celery_observability import _metrics_sync_engine

    engine = _metrics_sync_engine(database_url)
    with Session(engine) as session:
        rows = session.execute(
            select(TaskDeadLetter.queue, func.count())
            .where(TaskDeadLetter.status == DeadLetterStatus.PENDING)
            .group_by(TaskDeadLetter.queue)
        ).all()
    stats = {queue: float(count) for queue, count in rows}
    stats["pending_total"] = float(sum(stats.values()))
    return stats


def list_dead_letters(
    session: Session,
    *,
    status: DeadLetterStatus | None = DeadLetterStatus.PENDING,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[TaskDeadLetter], int]:
    stmt = select(TaskDeadLetter).order_by(TaskDeadLetter.created_at.desc())
    count_stmt = select(func.count()).select_from(TaskDeadLetter)
    if status is not None:
        stmt = stmt.where(TaskDeadLetter.status == status)
        count_stmt = count_stmt.where(TaskDeadLetter.status == status)
    total = session.scalar(count_stmt) or 0
    rows = list(session.scalars(stmt.offset(offset).limit(limit)).all())
    return rows, int(total)


def replay_dead_letter(
    session: Session,
    dead_letter_id: int,
    *,
    broker_url: str,
) -> TaskDeadLetter:
    row = session.get(TaskDeadLetter, dead_letter_id)
    if not row:
        raise LookupError("Dead letter not found")
    if row.status != DeadLetterStatus.PENDING:
        raise ValueError(f"Dead letter status is {row.status.value}, expected pending")

    args = json.loads(row.args_json or "[]")
    kwargs = json.loads(row.kwargs_json) if row.kwargs_json else {}
    correlation = kwargs.pop(CORRELATION_KWARG_KEY, None)
    if isinstance(correlation, dict):
        correlation = {**correlation, "replayed_from_dlq": row.id}

    new_task_id = send_task(
        row.task_name,
        args,
        broker_url=broker_url,
        kwargs=kwargs,
        queue=row.queue,
        correlation=correlation if isinstance(correlation, dict) else None,
    )
    row.status = DeadLetterStatus.REPLAYED
    row.replay_task_id = new_task_id
    row.replayed_at = datetime.now(UTC)
    session.commit()
    session.refresh(row)
    return row


def discard_dead_letter(session: Session, dead_letter_id: int) -> TaskDeadLetter:
    row = session.get(TaskDeadLetter, dead_letter_id)
    if not row:
        raise LookupError("Dead letter not found")
    if row.status != DeadLetterStatus.PENDING:
        raise ValueError(f"Dead letter status is {row.status.value}, expected pending")
    row.status = DeadLetterStatus.DISCARDED
    row.discarded_at = datetime.now(UTC)
    session.commit()
    session.refresh(row)
    return row


def persist_dead_letter_from_task(
    *,
    database_url: str,
    redis_url: str | None,
    celery_task_id: str | None,
    task_name: str,
    delivery_info: dict | None,
    args: list | tuple,
    kwargs: dict | None,
    exc: BaseException,
    traceback_text: str | None,
    retry_count: int,
) -> None:
    from secaudit_core.celery_observability import _metrics_sync_engine

    queue = _resolve_queue(task_name, delivery_info)
    engine = _metrics_sync_engine(database_url)
    with Session(engine) as session:
        record_dead_letter(
            session,
            celery_task_id=celery_task_id,
            task_name=task_name,
            queue=queue,
            args=args,
            kwargs=kwargs,
            exc=exc,
            traceback_text=traceback_text,
            retry_count=retry_count,
            redis_url=redis_url,
        )


def format_traceback(einfo) -> str | None:
    if einfo is None:
        return None
    try:
        return str(einfo)
    except Exception:
        return tb_module.format_exc()
