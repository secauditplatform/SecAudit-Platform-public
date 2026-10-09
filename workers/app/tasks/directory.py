from app.celery_app import celery_app, settings
from app.directory_sync_runner import run_directory_sync
from secaudit_core.celery_reliability import TASK_RETRY_KWARGS


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
