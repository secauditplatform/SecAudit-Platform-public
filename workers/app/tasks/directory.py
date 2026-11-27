from datetime import UTC, datetime

from sqlalchemy import select

from app.celery_app import celery_app, settings
from app.directory_sync_runner import run_directory_sync
from secaudit_core.beat_lock import acquire_beat_lock, release_beat_lock
from secaudit_core.celery_reliability import TASK_RETRY_KWARGS
from secaudit_core.models import DirectorySource, DirectorySync, JobStatus
from secaudit_core.task_outbox import enqueue_outbox_row


@celery_app.task(
    bind=True,
    name="app.tasks.directory.run_directory_sync_task",
    **TASK_RETRY_KWARGS,
)
def run_directory_sync_task(self, sync_id: int, **_kwargs) -> dict:
    run_directory_sync(
        sync_id,
        database_url=settings.database_url_sync,
        settings=settings,
    )
    return {"sync_id": sync_id}


@celery_app.task(name="app.tasks.directory.run_scheduled_directory_sources")
def run_scheduled_directory_sources() -> dict:
    lock_key = "beat:schedule_lock:directory_sources"
    lock_client, lock_token = acquire_beat_lock(
        settings.redis_url,
        lock_key,
        ttl_seconds=settings.beat_lock_ttl_seconds,
    )
    if lock_token is None:
        return {"skipped": True, "reason": "lock_not_acquired"}
    try:
        return _run_scheduled_directory_sources_locked()
    finally:
        release_beat_lock(lock_client, lock_key, lock_token)


def _run_scheduled_directory_sources_locked() -> dict:
    from croniter import croniter

    from app.tasks.compliance import SessionLocal

    now = datetime.now(UTC)
    triggered: list[int] = []

    with SessionLocal() as db:
        sources = (
            db.execute(
                select(DirectorySource).where(
                    DirectorySource.is_active.is_(True),
                    DirectorySource.is_scheduled.is_(True),
                    DirectorySource.cron_expression.isnot(None),
                )
            )
            .scalars()
            .all()
        )
        for source in sources:
            try:
                cron = croniter(source.cron_expression, now)
                prev_run = cron.get_prev(datetime)
            except (ValueError, KeyError):
                continue
            if source.last_scheduled_at and prev_run <= source.last_scheduled_at.replace(tzinfo=UTC):
                continue
            active = db.execute(
                select(DirectorySync.id).where(
                    DirectorySync.source_id == source.id,
                    DirectorySync.status.in_((JobStatus.PENDING, JobStatus.RUNNING)),
                )
            ).scalar_one_or_none()
            if active is not None:
                continue
            sync = DirectorySync(
                source_id=source.id,
                status=JobStatus.PENDING,
                owner_sub=source.owner_sub,
            )
            db.add(sync)
            db.flush()
            enqueue_outbox_row(
                db,
                task_name="app.tasks.directory.run_directory_sync_task",
                args=[sync.id],
                queue="inventory",
                callback_kind="directory_sync",
                callback_ref_id=sync.id,
                correlation={
                    "source": "schedule",
                    "directory_source_id": source.id,
                    "sync_id": sync.id,
                },
            )
            source.last_scheduled_at = now
            triggered.append(sync.id)
        db.commit()

    return {"triggered_syncs": triggered, "count": len(triggered)}
