"""Celery signal hooks for worker observability."""

from __future__ import annotations

import logging
import time

from celery.signals import task_failure, task_postrun, task_prerun

from secaudit_core.celery_observability import (
    CORRELATION_KWARG_KEY,
    log_task_event,
    record_task_metric,
)

_task_started_at: dict[str, float] = {}
_task_logger = logging.getLogger("secaudit.celery")


def _extract_correlation(kwargs: dict | None) -> dict | None:
    if not kwargs:
        return None
    value = kwargs.get(CORRELATION_KWARG_KEY)
    return value if isinstance(value, dict) else None


@task_prerun.connect
def _on_task_prerun(sender=None, task_id=None, task=None, args=None, kwargs=None, **_extra):
    if task_id:
        _task_started_at[task_id] = time.perf_counter()
    log_task_event(
        _task_logger,
        event="celery.task.start",
        task_name=sender.name if sender else "unknown",
        task_id=task_id,
        correlation=_extract_correlation(kwargs),
    )


@task_postrun.connect
def _on_task_postrun(sender=None, task_id=None, state=None, kwargs=None, **_extra):
    from app.celery_app import settings

    started = _task_started_at.pop(task_id, None) if task_id else None
    duration_ms = (time.perf_counter() - started) * 1000 if started is not None else None
    status = state or "SUCCESS"
    if duration_ms is not None:
        record_task_metric(
            settings.redis_url,
            task_name=sender.name if sender else "unknown",
            status=status,
            duration_ms=duration_ms,
        )
    log_task_event(
        _task_logger,
        event="celery.task.finish",
        task_name=sender.name if sender else "unknown",
        task_id=task_id,
        correlation=_extract_correlation(kwargs),
        duration_ms=duration_ms,
    )


@task_failure.connect
def _on_task_failure(sender=None, task_id=None, exception=None, kwargs=None, **_extra):
    from app.celery_app import settings

    record_task_metric(
        settings.redis_url,
        task_name=sender.name if sender else "unknown",
        status="FAILURE",
    )
    log_task_event(
        _task_logger,
        event="celery.task.failure",
        task_name=sender.name if sender else "unknown",
        task_id=task_id,
        correlation=_extract_correlation(kwargs),
        error=str(exception) if exception else None,
    )
