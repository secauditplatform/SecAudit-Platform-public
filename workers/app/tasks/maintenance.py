from datetime import UTC, datetime, timedelta

from secaudit_core.beat_lock import acquire_beat_lock, release_beat_lock
from secaudit_core.celery_observability import evaluate_worker_heartbeat, touch_beat_heartbeat
from secaudit_core.job_run_retention import purge_old_job_runs
from secaudit_core.enums import JobStatus, NotificationEventType
from secaudit_core.models import Job, JobRun, RemediationJob, RemediationRun
from secaudit_core.notifications import deliver_notifications, enqueue_platform_notification
from secaudit_core.redis_client import sync_redis
from secaudit_core.celery_reliability import (
    PENDING_ORPHAN_ERROR_MESSAGE,
    STALE_RUN_ERROR_MESSAGE,
    WORKER_LOST_ERROR_MESSAGE,
)
from secaudit_core.stale_runs import reconcile_worker_lost_runs, sweep_stale_runs
from secaudit_core.profiles_sync import sync_profiles_catalog
from secaudit_core.profiles_sync_status import record_catalog_sync_status
from secaudit_core.task_outbox import process_outbox_cycle
from secaudit_core.audit_flow_cleanup import cleanup_expired_audit_flow_runs
from secaudit_core.waivers import expire_due_waivers, find_expiring_waivers

from app.celery_app import celery_app, settings
from app.logging_pub import publish_job_log, publish_remediation_log
from app.notify import emit_run_notification
from app.tasks.compliance import SessionLocal


def _active_celery_task_ids() -> set[str] | None:
    try:
        inspector = celery_app.control.inspect(timeout=2.0)
        if inspector is None:
            return None
        task_ids: set[str] = set()
        for tasks_by_worker in (inspector.active() or {}, inspector.reserved() or {}):
            for tasks in tasks_by_worker.values():
                for task in tasks:
                    if isinstance(task, dict) and task.get("id"):
                        task_ids.add(str(task["id"]))
        return task_ids
    except Exception:
        return None


@celery_app.task(name="app.tasks.maintenance.send_notification")
def send_notification_task(payload: dict) -> dict:
    if not settings.notifications_enabled:
        return {"skipped": True, "reason": "notifications_disabled"}
    with SessionLocal() as db:
        return deliver_notifications(db, payload, settings)


@celery_app.task(name="app.tasks.maintenance.check_worker_heartbeat")
def check_worker_heartbeat_task() -> dict:
    lock_key = "beat:schedule_lock:worker_heartbeat"
    lock_client, lock_token = acquire_beat_lock(
        settings.redis_url,
        lock_key,
        ttl_seconds=settings.beat_lock_ttl_seconds,
    )
    if lock_token is None:
        return {"skipped": True, "reason": "lock_not_acquired"}

    try:
        touch_beat_heartbeat(settings.redis_url, ttl_seconds=max(180, settings.beat_lock_ttl_seconds * 3))
        result = evaluate_worker_heartbeat(
            settings.redis_url,
            max_age_seconds=settings.worker_heartbeat_max_age_seconds,
        )
        transition = result.get("transition")
        age = result.get("age_seconds")
        max_age = int(result["max_age_seconds"])

        if transition == "stale":
            detail = (
                f"Heartbeat timestamp missing (max age {max_age}s)"
                if age is None
                else f"Heartbeat age {int(age)}s exceeds max {max_age}s"
            )
            enqueue_platform_notification(
                broker_url=settings.celery_broker_url,
                settings=settings,
                trigger_events=[NotificationEventType.WORKER_HEARTBEAT_STALE.value],
                status="failed",
                summary="Celery worker heartbeat is stale — workers may be down or blocked",
                detail=detail,
                age_seconds=age if isinstance(age, (int, float)) else None,
                max_age_seconds=max_age,
            )
        elif transition == "recovered":
            enqueue_platform_notification(
                broker_url=settings.celery_broker_url,
                settings=settings,
                trigger_events=[NotificationEventType.WORKER_HEARTBEAT_RECOVERED.value],
                status="ok",
                summary="Celery worker heartbeat recovered",
                detail=(
                    f"Heartbeat age {int(age)}s (max {max_age}s)"
                    if isinstance(age, (int, float))
                    else f"Heartbeat healthy again (max {max_age}s)"
                ),
                age_seconds=age if isinstance(age, (int, float)) else None,
                max_age_seconds=max_age,
            )

        return {
            "stale": bool(result["stale"]),
            "age_seconds": age,
            "state": result["state"],
            "transition": transition,
            "notified": transition is not None,
        }
    finally:
        release_beat_lock(lock_client, lock_key, lock_token)


@celery_app.task(name="app.tasks.maintenance.purge_old_job_runs")
def purge_old_job_runs_task() -> dict:
    lock_key = "beat:schedule_lock:purge_old_job_runs"
    lock_client, lock_token = acquire_beat_lock(
        settings.redis_url,
        lock_key,
        ttl_seconds=settings.beat_lock_ttl_seconds,
    )
    if lock_token is None:
        return {"skipped": True, "reason": "lock_not_acquired"}
    try:
        touch_beat_heartbeat(settings.redis_url, ttl_seconds=max(180, settings.beat_lock_ttl_seconds * 3))
        from secaudit_core.runtime_settings import get_job_run_retention_days

        with SessionLocal() as db:
            return purge_old_job_runs(
                db,
                retention_days=get_job_run_retention_days(
                    settings.redis_url,
                    env_default=settings.job_run_retention_days,
                ),
            )
    finally:
        release_beat_lock(lock_client, lock_key, lock_token)


@celery_app.task(name="app.tasks.maintenance.cleanup_expired_audit_flow_runs")
def cleanup_expired_audit_flow_runs_task() -> dict:
    lock_key = "beat:schedule_lock:cleanup_expired_audit_flow_runs"
    lock_client, lock_token = acquire_beat_lock(
        settings.redis_url,
        lock_key,
        ttl_seconds=settings.beat_lock_ttl_seconds,
    )
    if lock_token is None:
        return {"skipped": True, "reason": "lock_not_acquired"}
    try:
        with SessionLocal() as db:
            return cleanup_expired_audit_flow_runs(db)
    finally:
        release_beat_lock(lock_client, lock_key, lock_token)


@celery_app.task(name="app.tasks.maintenance.expire_compliance_waivers")
def expire_compliance_waivers_task() -> dict:
    lock_key = "beat:schedule_lock:expire_waivers"
    lock_client, lock_token = acquire_beat_lock(
        settings.redis_url,
        lock_key,
        ttl_seconds=settings.beat_lock_ttl_seconds,
    )
    if lock_token is None:
        return {"skipped": True, "reason": "lock_not_acquired"}

    try:
        with SessionLocal() as db:
            notified = _notify_expiring_waivers(db)
            expired_ids = expire_due_waivers(db)
            db.commit()
        return {
            "expired": expired_ids,
            "count": len(expired_ids),
            "expiring_notified": notified,
        }
    finally:
        release_beat_lock(lock_client, lock_key, lock_token)


def _notify_expiring_waivers(db) -> int:
    waivers = find_expiring_waivers(db, within_days=settings.waiver_expiring_days)
    if not waivers:
        return 0
    client = sync_redis(settings.redis_url, decode_responses=True)
    notified = 0
    try:
        for waiver in waivers:
            expires = waiver.expires_at
            if expires is None:
                continue
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=UTC)
            dedupe_key = f"waiver_expiring_notified:{waiver.id}:{expires.date().isoformat()}"
            # Keep the flag until after expiry so the 5-minute beat does not re-spam.
            ttl = max(3600, int((expires - datetime.now(UTC)).total_seconds()) + 86400)
            if not client.set(dedupe_key, "1", nx=True, ex=ttl):
                continue
            days_left = max(0, (expires.date() - datetime.now(UTC).date()).days)
            enqueue_platform_notification(
                broker_url=settings.celery_broker_url,
                settings=settings,
                trigger_events=[NotificationEventType.WAIVER_EXPIRING.value],
                status="warning",
                summary=(
                    f"Waiver #{waiver.id} for {waiver.rule_tech_name} expires in {days_left} day(s)"
                ),
                detail=(
                    f"profile_id={waiver.profile_id}; host_id={waiver.host_id}; "
                    f"expires_at={expires.isoformat()}; reason={waiver.reason or ''}"
                ),
            )
            notified += 1
    finally:
        client.close()
    return notified


@celery_app.task(name="app.tasks.maintenance.sync_profiles_catalog")
def sync_profiles_catalog_task() -> dict:
    lock_key = "beat:schedule_lock:profiles_catalog_sync"
    lock_client, lock_token = acquire_beat_lock(
        settings.redis_url,
        lock_key,
        ttl_seconds=settings.beat_lock_ttl_seconds,
    )
    if lock_token is None:
        return {"skipped": True, "reason": "lock_not_acquired"}

    try:
        if not settings.profiles_catalog_sync_enabled:
            result = {"skipped": True, "reason": "profiles_catalog_sync_disabled"}
            record_catalog_sync_status(settings.redis_url, result)
            return result

        with SessionLocal() as db:
            result = sync_profiles_catalog(
                db,
                settings,
                update_existing=settings.profiles_catalog_sync_update_existing,
            )
            db.commit()
        record_catalog_sync_status(settings.redis_url, result)
        return result
    finally:
        release_beat_lock(lock_client, lock_key, lock_token)


@celery_app.task(name="app.tasks.maintenance.sweep_stale_runs")
def sweep_stale_runs_task() -> dict:
    lock_key = "beat:schedule_lock:sweep_stale_runs"
    lock_client, lock_token = acquire_beat_lock(
        settings.redis_url,
        lock_key,
        ttl_seconds=settings.beat_lock_ttl_seconds,
    )
    if lock_token is None:
        return {"skipped": True, "reason": "lock_not_acquired"}

    try:
        now = datetime.now(UTC)
        running_cutoff = now - timedelta(seconds=settings.stale_run_timeout_effective)
        pending_cutoff = now - timedelta(seconds=settings.pending_orphan_timeout_effective)
        pending_notifications: list[dict] = []

        with SessionLocal() as db:
            result = sweep_stale_runs(db, running_cutoff, pending_cutoff=pending_cutoff)
            worker_lost = {"job_runs": [], "remediation_runs": []}
            active_task_ids = _active_celery_task_ids()
            if active_task_ids is not None:
                worker_lost = reconcile_worker_lost_runs(db, active_task_ids)

            for run_id in result["job_runs"] + result["pending_job_runs"] + worker_lost["job_runs"]:
                job_run = db.get(JobRun, run_id)
                if not job_run:
                    continue
                job = db.get(Job, job_run.job_id)
                pending_notifications.append(
                    {
                        "run_kind": "job",
                        "run_id": job_run.id,
                        "job_id": job_run.job_id,
                        "job_name": job.name if job else f"Job #{job_run.job_id}",
                        "status": JobStatus.FAILED,
                        "error_message": job_run.error_message,
                        "source": "stale",
                        "owner_sub": job.owner_sub if job else None,
                    }
                )

            for run_id in (
                result["remediation_runs"]
                + result["pending_remediation_runs"]
                + worker_lost["remediation_runs"]
            ):
                remediation_run = db.get(RemediationRun, run_id)
                if not remediation_run:
                    continue
                job = db.get(RemediationJob, remediation_run.remediation_job_id)
                pending_notifications.append(
                    {
                        "run_kind": "remediation",
                        "run_id": remediation_run.id,
                        "job_id": remediation_run.remediation_job_id,
                        "job_name": (
                            job.name if job else f"Remediation #{remediation_run.remediation_job_id}"
                        ),
                        "status": JobStatus.FAILED,
                        "error_message": remediation_run.error_message,
                        "source": "stale",
                        "owner_sub": job.owner_sub if job else None,
                    }
                )

            db.commit()

        for run_id in worker_lost["job_runs"]:
            publish_job_log(run_id, WORKER_LOST_ERROR_MESSAGE, level="error")
        for run_id in worker_lost["remediation_runs"]:
            publish_remediation_log(run_id, WORKER_LOST_ERROR_MESSAGE, level="error")

        for item in pending_notifications:
            emit_run_notification(settings, **item)

        all_job = result["job_runs"] + result["pending_job_runs"] + worker_lost["job_runs"]
        all_remediation = (
            result["remediation_runs"]
            + result["pending_remediation_runs"]
            + worker_lost["remediation_runs"]
        )
        return {
            "job_runs_failed": all_job,
            "remediation_runs_failed": all_remediation,
            "count": len(all_job) + len(all_remediation),
        }
    finally:
        release_beat_lock(lock_client, lock_key, lock_token)


@celery_app.task(name="app.tasks.maintenance.dispatch_outbox")
def dispatch_outbox_task() -> dict:
    lock_key = "beat:schedule_lock:dispatch_outbox"
    lock_client, lock_token = acquire_beat_lock(
        settings.redis_url,
        lock_key,
        ttl_seconds=settings.beat_lock_ttl_seconds,
    )
    if lock_token is None:
        return {"skipped": True, "reason": "lock_not_acquired"}

    try:
        with SessionLocal() as db:
            result = process_outbox_cycle(
                db,
                broker_url=settings.celery_broker_url,
                metrics_redis_url=settings.redis_url,
                limit=settings.outbox_poll_batch_size,
            )
            db.commit()
        return result
    finally:
        release_beat_lock(lock_client, lock_key, lock_token)
