from functools import lru_cache

from celery import Celery

from secaudit_core.celery_observability import CORRELATION_KWARG_KEY
from secaudit_core.celery_redis import create_celery_app
from secaudit_core.settings import SecAuditSettings


def _settings_key(settings: SecAuditSettings) -> str:
    transport = settings.celery_transport_options()
    return (
        f"{settings.celery_broker_url_effective}|"
        f"{transport.get('master_name', '')}|"
        f"{bool(transport)}"
    )


@lru_cache
def _celery_client(cache_key: str) -> Celery:
    settings = SecAuditSettings()
    return create_celery_app("secaudit", settings)


def send_task(
    task_name: str,
    args: list,
    *,
    broker_url: str,
    kwargs: dict | None = None,
    queue: str | None = None,
    correlation: dict | None = None,
    headers: dict | None = None,
    task_id: str | None = None,
) -> str:
    """Dispatch a Celery task and return the task id.

    The active OpenTelemetry context (when tracing is enabled) is injected
    into task headers so worker-side spans stay linked to the calling request.
    """
    from secaudit_core.tracing import inject_context, start_span

    settings = SecAuditSettings()
    _ = broker_url  # kept for API compatibility; Sentinel uses settings-derived broker URL
    payload = dict(kwargs or {})
    if correlation:
        payload[CORRELATION_KWARG_KEY] = correlation

    combined_headers: dict = dict(headers or {})
    inject_context(combined_headers)

    options: dict = {}
    if queue:
        options["queue"] = queue
    if combined_headers:
        options["headers"] = combined_headers
    if task_id:
        options["task_id"] = task_id

    span_attrs = {
        "messaging.system": "celery",
        "messaging.destination": queue or "default",
        "secaudit.task_name": task_name,
    }
    with start_span(f"celery.dispatch {task_name}", attributes=span_attrs, kind="producer"):
        result = _celery_client(_settings_key(settings)).send_task(
            task_name,
            args=args,
            kwargs=payload,
            **options,
        )
    return result.id


def revoke_task(task_id: str, *, broker_url: str) -> None:
    """Revoke a Celery task (best-effort)."""
    _ = broker_url
    try:
        settings = SecAuditSettings()
        _celery_client(_settings_key(settings)).control.revoke(task_id, terminate=True, signal="SIGTERM")
    except Exception:
        pass
