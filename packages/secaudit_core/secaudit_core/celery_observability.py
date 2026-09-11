"""Celery/worker observability helpers stored in Redis."""

from __future__ import annotations

import json
import logging
import threading
from datetime import UTC, datetime

import redis

from secaudit_core.redis_client import sync_redis

CORRELATION_KWARG_KEY = "_secaudit_correlation"

WORKER_HEARTBEAT_KEY = "secaudit:worker:heartbeat:last_seen"
WORKER_HEARTBEAT_ALERT_STATE_KEY = "secaudit:worker:heartbeat:alert_state"
CELERY_METRICS_PREFIX = "secaudit:metrics:celery"
OUTBOX_METRICS_PREFIX = "secaudit:metrics:outbox"
KNOWN_QUEUES = ("compliance", "remediation", "inventory", "maintenance")

logger = logging.getLogger(__name__)

_sync_engines: dict[str, object] = {}
_sync_engines_lock = threading.Lock()


def redis_client(
    redis_url: str,
    *,
    socket_connect_timeout: float = 2.0,
    socket_timeout: float = 2.0,
) -> redis.Redis:
    return sync_redis(
        redis_url,
        socket_connect_timeout=socket_connect_timeout,
        socket_timeout=socket_timeout,
    )


def touch_worker_heartbeat(redis_url: str, *, ttl_seconds: int = 120) -> None:
    client = redis_client(redis_url)
    try:
        client.set(WORKER_HEARTBEAT_KEY, datetime.now(UTC).isoformat(), ex=ttl_seconds)
    finally:
        client.close()


def worker_heartbeat_age_seconds(redis_url: str) -> float | None:
    client = redis_client(redis_url)
    try:
        value = client.get(WORKER_HEARTBEAT_KEY)
        if not value:
            return None
        last_seen = datetime.fromisoformat(value)
        if last_seen.tzinfo is None:
            last_seen = last_seen.replace(tzinfo=UTC)
        return (datetime.now(UTC) - last_seen).total_seconds()
    finally:
        client.close()


def get_worker_heartbeat_alert_state(redis_url: str) -> str | None:
    client = redis_client(redis_url)
    try:
        value = client.get(WORKER_HEARTBEAT_ALERT_STATE_KEY)
        return str(value) if value else None
    finally:
        client.close()


def set_worker_heartbeat_alert_state(redis_url: str, state: str, *, ttl_seconds: int = 86400) -> None:
    client = redis_client(redis_url)
    try:
        client.set(WORKER_HEARTBEAT_ALERT_STATE_KEY, state, ex=ttl_seconds)
    finally:
        client.close()


def evaluate_worker_heartbeat(
    redis_url: str,
    *,
    max_age_seconds: int,
) -> dict[str, float | str | bool | None]:
    """Edge-triggered heartbeat health evaluation.

    Returns ``transition`` of ``"stale"``, ``"recovered"``, or ``None`` when
    the health state did not change.
    """
    age = worker_heartbeat_age_seconds(redis_url)
    is_stale = age is None or age > max_age_seconds
    previous = get_worker_heartbeat_alert_state(redis_url)
    desired = "stale" if is_stale else "ok"
    transition: str | None = None

    if desired == "stale" and previous != "stale":
        transition = "stale"
    elif desired == "ok" and previous == "stale":
        transition = "recovered"

    if previous != desired:
        set_worker_heartbeat_alert_state(redis_url, desired)

    return {
        "stale": is_stale,
        "age_seconds": age,
        "previous_state": previous,
        "state": desired,
        "transition": transition,
        "max_age_seconds": max_age_seconds,
    }


def record_task_metric(
    redis_url: str,
    *,
    task_name: str,
    status: str,
    duration_ms: float | None = None,
) -> None:
    client = redis_client(redis_url)
    try:
        client.hincrby(f"{CELERY_METRICS_PREFIX}:task_total", f"{task_name}|{status}", 1)
        if duration_ms is not None:
            client.hincrbyfloat(
                f"{CELERY_METRICS_PREFIX}:task_duration_ms_sum",
                task_name,
                duration_ms,
            )
    finally:
        client.close()


def queue_depths(redis_url: str) -> dict[str, int]:
    client = redis_client(redis_url)
    try:
        depths: dict[str, int] = {}
        for queue in KNOWN_QUEUES:
            depths[queue] = int(client.llen(queue) or 0)
        return depths
    finally:
        client.close()


def record_outbox_dispatch_lag(redis_url: str, lag_seconds: float) -> None:
    client = redis_client(redis_url)
    try:
        client.incrbyfloat(f"{OUTBOX_METRICS_PREFIX}:dispatch_lag_seconds_sum", lag_seconds)
        client.incr(f"{OUTBOX_METRICS_PREFIX}:dispatch_lag_seconds_count")
    finally:
        client.close()


def record_outbox_dispatch_failure(redis_url: str) -> None:
    client = redis_client(redis_url)
    try:
        client.incr(f"{OUTBOX_METRICS_PREFIX}:dispatch_failures_total")
    finally:
        client.close()


def _metrics_sync_engine(database_url: str):
    from sqlalchemy import create_engine

    with _sync_engines_lock:
        engine = _sync_engines.get(database_url)
        if engine is None:
            engine = create_engine(
                database_url,
                pool_pre_ping=True,
                pool_size=1,
                max_overflow=0,
            )
            _sync_engines[database_url] = engine
        return engine


def fetch_outbox_stats(database_url: str) -> dict[str, float | None]:
    from sqlalchemy import func, select
    from sqlalchemy.orm import Session

    from secaudit_core.enums import OutboxStatus
    from secaudit_core.models import TaskOutbox

    now = datetime.now(UTC)
    engine = _metrics_sync_engine(database_url)
    with Session(engine) as session:
        pending = (
            session.scalar(
                select(func.count())
                .select_from(TaskOutbox)
                .where(TaskOutbox.status == OutboxStatus.PENDING)
            )
            or 0
        )
        dispatching = (
            session.scalar(
                select(func.count())
                .select_from(TaskOutbox)
                .where(TaskOutbox.status == OutboxStatus.DISPATCHING)
            )
            or 0
        )
        oldest_created = session.scalar(
            select(func.min(TaskOutbox.created_at)).where(
                TaskOutbox.status == OutboxStatus.PENDING
            )
        )
        oldest_dispatch = session.scalar(
            select(func.min(TaskOutbox.dispatch_started_at)).where(
                TaskOutbox.status == OutboxStatus.DISPATCHING
            )
        )

    oldest_pending_age: float | None = None
    if oldest_created is not None:
        created = oldest_created
        if created.tzinfo is None:
            created = created.replace(tzinfo=UTC)
        oldest_pending_age = (now - created).total_seconds()

    oldest_dispatching_age: float | None = None
    if oldest_dispatch is not None:
        started = oldest_dispatch
        if started.tzinfo is None:
            started = started.replace(tzinfo=UTC)
        oldest_dispatching_age = (now - started).total_seconds()

    return {
        "pending": float(pending),
        "dispatching": float(dispatching),
        "oldest_pending_age_seconds": oldest_pending_age,
        "oldest_dispatching_age_seconds": oldest_dispatching_age,
    }


def _render_outbox_redis_metrics(client: redis.Redis) -> list[str]:
    lines: list[str] = []
    lag_sum = client.get(f"{OUTBOX_METRICS_PREFIX}:dispatch_lag_seconds_sum") or "0"
    lag_count = client.get(f"{OUTBOX_METRICS_PREFIX}:dispatch_lag_seconds_count") or "0"
    failures = client.get(f"{OUTBOX_METRICS_PREFIX}:dispatch_failures_total") or "0"
    lines.append(f"secaudit_outbox_dispatch_lag_seconds_sum {lag_sum}")
    lines.append(f"secaudit_outbox_dispatch_lag_seconds_count {lag_count}")
    lines.append(f"secaudit_outbox_dispatch_failures_total {failures}")
    return lines


def _render_outbox_db_metrics(outbox_stats: dict[str, float | None]) -> list[str]:
    lines: list[str] = []
    lines.append(f"secaudit_outbox_pending {int(outbox_stats['pending'])}")
    lines.append(f"secaudit_outbox_dispatching {int(outbox_stats['dispatching'])}")
    pending_age = outbox_stats.get("oldest_pending_age_seconds")
    lines.append(
        "secaudit_outbox_oldest_pending_age_seconds "
        f"{pending_age if pending_age is not None else -1}"
    )
    dispatch_age = outbox_stats.get("oldest_dispatching_age_seconds")
    lines.append(
        "secaudit_outbox_oldest_dispatching_age_seconds "
        f"{dispatch_age if dispatch_age is not None else -1}"
    )
    return lines


DLQ_METRICS_PREFIX = "secaudit:metrics:dlq"


def _render_dlq_redis_metrics(client: redis.Redis) -> list[str]:
    lines: list[str] = []
    dead_lettered = client.hgetall(f"{DLQ_METRICS_PREFIX}:dead_lettered_total") or {}
    for queue, count in sorted(dead_lettered.items()):
        labels = f'queue="{queue}"'
        lines.append(f"secaudit_celery_tasks_dead_lettered_total{{{labels}}} {count}")
    return lines


def _render_dlq_db_metrics(dlq_stats: dict[str, float]) -> list[str]:
    lines: list[str] = []
    pending_total = dlq_stats.get("pending_total", 0.0)
    lines.append(f"secaudit_celery_dlq_pending_total {int(pending_total)}")
    for queue in KNOWN_QUEUES:
        count = dlq_stats.get(queue, 0.0)
        labels = f'queue="{queue}"'
        lines.append(f"secaudit_celery_dlq_pending{{{labels}}} {int(count)}")
    return lines


def render_celery_prometheus_metrics(
    redis_url: str,
    *,
    broker_url: str | None = None,
    outbox_stats: dict[str, float | None] | None = None,
    dlq_stats: dict[str, float] | None = None,
    socket_connect_timeout: float = 2.0,
    socket_timeout: float = 2.0,
    return_error: bool = False,
) -> str | tuple[str, str | None]:
    lines: list[str] = []
    error: str | None = None
    broker = broker_url or redis_url
    try:
        client = redis_client(
            redis_url,
            socket_connect_timeout=socket_connect_timeout,
            socket_timeout=socket_timeout,
        )
    except Exception as exc:
        logger.warning("Failed to connect Redis for Celery metrics: %s", exc)
        empty = ""
        return (empty, str(exc)) if return_error else empty

    try:
        task_totals = client.hgetall(f"{CELERY_METRICS_PREFIX}:task_total") or {}
        for key, count in sorted(task_totals.items()):
            task_name, status = key.split("|", 1)
            labels = f'task="{task_name}",status="{status}"'
            lines.append(f"secaudit_celery_tasks_total{{{labels}}} {count}")

        duration_sums = client.hgetall(f"{CELERY_METRICS_PREFIX}:task_duration_ms_sum") or {}
        for task_name, total_ms in sorted(duration_sums.items()):
            labels = f'task="{task_name}"'
            lines.append(f"secaudit_celery_task_duration_ms_sum{{{labels}}} {total_ms}")

        lines.extend(_render_outbox_redis_metrics(client))
        lines.extend(_render_dlq_redis_metrics(client))

        heartbeat_raw = client.get(WORKER_HEARTBEAT_KEY)
        if not heartbeat_raw:
            lines.append("secaudit_worker_heartbeat_age_seconds -1")
            lines.append("secaudit_worker_heartbeat_stale 1")
        else:
            try:
                last_seen = datetime.fromisoformat(str(heartbeat_raw))
                if last_seen.tzinfo is None:
                    last_seen = last_seen.replace(tzinfo=UTC)
                age = (datetime.now(UTC) - last_seen).total_seconds()
                lines.append(f"secaudit_worker_heartbeat_age_seconds {age}")
                lines.append("secaudit_worker_heartbeat_stale 0")
            except (TypeError, ValueError):
                lines.append("secaudit_worker_heartbeat_age_seconds -1")
                lines.append("secaudit_worker_heartbeat_stale 1")
    except Exception as exc:
        logger.warning("Celery metrics scrape error: %s", exc)
        error = str(exc)
        lines = []
    finally:
        client.close()

    if not error:
        try:
            broker_client = redis_client(
                broker,
                socket_connect_timeout=socket_connect_timeout,
                socket_timeout=socket_timeout,
            )
            try:
                for queue in KNOWN_QUEUES:
                    depth = int(broker_client.llen(queue) or 0)
                    labels = f'queue="{queue}"'
                    lines.append(f"secaudit_celery_queue_depth{{{labels}}} {depth}")
            finally:
                broker_client.close()
        except Exception as exc:
            logger.warning("Celery queue depth scrape error: %s", exc)
            error = str(exc)
            lines = []

    if outbox_stats is not None and not error:
        lines.extend(_render_outbox_db_metrics(outbox_stats))

    if dlq_stats is not None and not error:
        lines.extend(_render_dlq_db_metrics(dlq_stats))

    body = "\n".join(lines) + ("\n" if lines else "")
    if return_error:
        return body, error
    return body


def log_task_event(
    logger,
    *,
    event: str,
    task_name: str,
    task_id: str | None,
    correlation: dict | None,
    duration_ms: float | None = None,
    error: str | None = None,
) -> None:
    payload = {
        "event": event,
        "task_name": task_name,
        "task_id": task_id,
        "correlation": correlation or {},
    }
    if duration_ms is not None:
        payload["duration_ms"] = round(duration_ms, 2)
    if error:
        payload["error"] = error
    logger.info(json.dumps(payload, ensure_ascii=False))
