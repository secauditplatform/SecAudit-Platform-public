from app.audit_flow_runner import run_audit_flow_reprobe_sync, run_audit_flow_scan_sync
from app.celery_app import celery_app, settings
from app.logging_pub import publish_audit_flow_log
from secaudit_core.celery_reliability import TASK_RETRY_KWARGS


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
