from secaudit_core.enums import JobStatus
from secaudit_core.notifications import enqueue_run_notification, events_for_terminal_status
from secaudit_core.settings import SecAuditSettings


def emit_run_notification(
    settings: SecAuditSettings,
    *,
    run_kind: str,
    run_id: int,
    job_id: int | None,
    job_name: str,
    status: JobStatus | str,
    error_message: str | None = None,
    owner_sub: str | None = None,
    source: str = "finished",
) -> None:
    status_value = status.value if isinstance(status, JobStatus) else str(status)
    trigger_events = events_for_terminal_status(status_value, source=source)
    enqueue_run_notification(
        broker_url=settings.celery_broker_url,
        settings=settings,
        trigger_events=trigger_events,
        run_kind=run_kind,
        run_id=run_id,
        job_id=job_id,
        job_name=job_name,
        status=status_value,
        error_message=error_message,
        owner_sub=owner_sub,
    )
