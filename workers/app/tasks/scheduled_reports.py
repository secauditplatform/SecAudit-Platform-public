import logging
from datetime import UTC, datetime

from sqlalchemy import select

from app.celery_app import celery_app, settings
from app.tasks.compliance import SessionLocal
from secaudit_core.beat_lock import acquire_beat_lock, release_beat_lock
from secaudit_core.models import ScheduledReport
from secaudit_core.scheduled_reports import deliver_scheduled_report, should_trigger_schedule

logger = logging.getLogger(__name__)


@celery_app.task(name="app.tasks.scheduled_reports.deliver_report")
def deliver_report_task(schedule_id: int, run_id: int | None = None) -> dict:
    with SessionLocal() as db:
        schedule = db.get(ScheduledReport, schedule_id)
        if not schedule:
            return {"delivered": False, "reason": "schedule_not_found"}
        result = deliver_scheduled_report(db, schedule, settings, run_id=run_id)
        db.commit()
        return result


@celery_app.task(name="app.tasks.scheduled_reports.run_scheduled_reports")
def run_scheduled_reports() -> dict:
    lock_key = "beat:schedule_lock:scheduled_reports"
    lock_client, lock_token = acquire_beat_lock(
        settings.redis_url,
        lock_key,
        ttl_seconds=settings.beat_lock_ttl_seconds,
    )
    if lock_token is None:
        return {"skipped": True, "reason": "lock_not_acquired"}

    try:
        return _run_scheduled_reports_locked()
    finally:
        release_beat_lock(lock_client, lock_key, lock_token)


def _run_scheduled_reports_locked() -> dict:
    if not settings.scheduled_reports_enabled:
        return {"skipped": True, "reason": "scheduled_reports_disabled"}

    now = datetime.now(UTC)
    triggered: list[int] = []
    skipped: list[int] = []
    errors: dict[int, str] = {}

    with SessionLocal() as db:
        schedules = db.execute(
            select(ScheduledReport).where(ScheduledReport.is_active.is_(True))
        ).scalars().all()

        for schedule in schedules:
            if not should_trigger_schedule(schedule, now):
                skipped.append(schedule.id)
                continue
            try:
                result = deliver_scheduled_report(db, schedule, settings)
                if result.get("delivered"):
                    triggered.append(schedule.id)
                else:
                    skipped.append(schedule.id)
            except Exception as exc:
                logger.warning(
                    "Scheduled report delivery failed for schedule id=%s: %s",
                    schedule.id,
                    exc,
                    exc_info=True,
                )
                errors[schedule.id] = str(exc)

        db.commit()

    return {
        "triggered": triggered,
        "skipped": skipped,
        "errors": errors,
        "count": len(triggered),
    }
