from app.celery_app import celery_app, settings
from app.inventory_scan_runner import run_inventory_scan_sync
from secaudit_core.celery_reliability import TASK_RETRY_KWARGS


@celery_app.task(
    bind=True,
    name="app.tasks.inventory.run_inventory_scan_task",
    **TASK_RETRY_KWARGS,
)
def run_inventory_scan_task(self, scan_id: int, **_kwargs) -> dict:
    run_inventory_scan_sync(
        scan_id,
        database_url=settings.database_url_sync,
        redis_url=settings.redis_url,
    )
    return {"scan_id": scan_id}
