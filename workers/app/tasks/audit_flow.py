from datetime import UTC, datetime

from sqlalchemy import select

from app.celery_app import celery_app, settings
from app.audit_flow_runner import run_audit_flow_reprobe_sync, run_audit_flow_scan_sync
from app.logging_pub import publish_audit_flow_log
from secaudit_core.audit_flow_scope import compose_template_targets, load_inventory_scope_hosts, normalize_inventory_scope
from secaudit_core.beat_lock import acquire_beat_lock, release_beat_lock
from secaudit_core.celery_reliability import TASK_RETRY_KWARGS
from secaudit_core.enums import AuditFlowStatus, CredentialType
from secaudit_core.models import AuditFlowCredential, AuditFlowRun, AuditFlowTemplate
from secaudit_core.task_outbox import enqueue_outbox_row


@celery_app.task(
    bind=True,
    name="app.tasks.audit_flow.run_audit_flow_scan_task",
    **TASK_RETRY_KWARGS,
)
def run_audit_flow_scan_task(self, run_id: int, **_kwargs) -> dict:
    publish_audit_flow_log(run_id, f"Worker picked up task #{run_id}")
    run_audit_flow_scan_sync(
        run_id,
        database_url=settings.database_url_sync,
        redis_url=settings.redis_url,
    )
    return {"audit_flow_run_id": run_id}


@celery_app.task(
    bind=True,
    name="app.tasks.audit_flow.run_audit_flow_reprobe_task",
    **TASK_RETRY_KWARGS,
)
def run_audit_flow_reprobe_task(
    self, run_id: int, credential_id: int | None = None, host_ids: list[int] | None = None, **_kwargs
) -> dict:
    publish_audit_flow_log(run_id, f"Worker re-probing task #{run_id}")
    run_audit_flow_reprobe_sync(
        run_id,
        database_url=settings.database_url_sync,
        redis_url=settings.redis_url,
        credential_id=credential_id,
        host_ids=host_ids,
    )
    return {"audit_flow_run_id": run_id, "reprobe": True}


@celery_app.task(name="app.tasks.audit_flow.run_scheduled_audit_flow_templates")
def run_scheduled_audit_flow_templates() -> dict:
    lock_key = "beat:schedule_lock:audit_flow_templates"
    lock_client, lock_token = acquire_beat_lock(
        settings.redis_url,
        lock_key,
        ttl_seconds=settings.beat_lock_ttl_seconds,
    )
    if lock_token is None:
        return {"skipped": True, "reason": "lock_not_acquired"}

    try:
        return _run_scheduled_audit_flow_templates_locked()
    finally:
        release_beat_lock(lock_client, lock_key, lock_token)


def _attach_snapshot_credentials(db, run_id: int, snapshots: list) -> None:
    for item in snapshots or []:
        cred_type = item.get("credential_type")
        if isinstance(cred_type, str):
            cred_type = CredentialType(cred_type)
        db.add(
            AuditFlowCredential(
                run_id=run_id,
                label=str(item.get("label") or "pair")[:128],
                credential_type=cred_type,
                username=str(item.get("username") or "")[:128],
                encrypted_secret=str(item["encrypted_secret"]),
                encrypted_key_passphrase=item.get("encrypted_key_passphrase"),
                service_username=(
                    str(item["service_username"])[:128] if item.get("service_username") else None
                ),
                encrypted_service_secret=item.get("encrypted_service_secret"),
            )
        )


def _run_scheduled_audit_flow_templates_locked() -> dict:
    from croniter import croniter

    from app.tasks.compliance import SessionLocal

    now = datetime.now(UTC)
    triggered: list[int] = []
    skipped: list[int] = []

    with SessionLocal() as db:
        templates = (
            db.execute(
                select(AuditFlowTemplate).where(
                    AuditFlowTemplate.is_active.is_(True),
                    AuditFlowTemplate.is_scheduled.is_(True),
                    AuditFlowTemplate.cron_expression.isnot(None),
                )
            )
            .scalars()
            .all()
        )

        for template in templates:
            try:
                cron = croniter(template.cron_expression, now)
                prev_run = cron.get_prev(datetime)
            except (ValueError, KeyError):
                continue

            if template.last_scheduled_at and prev_run <= template.last_scheduled_at.replace(tzinfo=UTC):
                continue

            scope = normalize_inventory_scope(template.inventory_scope_json)
            try:
                hosts = (
                    load_inventory_scope_hosts(db, scope, owner_sub=template.owner_sub)
                    if scope is not None
                    else []
                )
                targets = compose_template_targets(
                    list(template.targets_json or []),
                    hosts,
                    scope_active=scope is not None,
                )
            except ValueError:
                skipped.append(template.id)
                continue

            run = AuditFlowRun(
                status=AuditFlowStatus.PENDING,
                targets_json=targets,
                save_to_inventory=bool(template.save_to_inventory),
                template_id=template.id,
                owner_sub=template.owner_sub,
            )
            db.add(run)
            db.flush()
            _attach_snapshot_credentials(db, run.id, template.credentials_json or [])
            enqueue_outbox_row(
                db,
                task_name="app.tasks.audit_flow.run_audit_flow_scan_task",
                args=[run.id],
                queue="inventory",
                callback_kind="audit_flow_run",
                callback_ref_id=run.id,
                correlation={
                    "source": "schedule",
                    "audit_flow_template_id": template.id,
                    "audit_flow_run_id": run.id,
                },
            )
            template.last_scheduled_at = now
            triggered.append(run.id)

        db.commit()

    return {"triggered_runs": triggered, "count": len(triggered), "skipped_templates": skipped}
