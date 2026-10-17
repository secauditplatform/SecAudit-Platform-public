from secaudit_core.aag_client import AAG_MAX_TIMEOUT_SECONDS

from app.aag_runner import run_aag_artifact
from app.celery_app import celery_app, settings


@celery_app.task(
    name="app.tasks.aag.run_aag_task",
    soft_time_limit=AAG_MAX_TIMEOUT_SECONDS + 60,
    time_limit=AAG_MAX_TIMEOUT_SECONDS + 180,
)
def run_aag_task(artifact_id: int, **_kwargs) -> dict:
    run_aag_artifact(
        int(artifact_id),
        database_url=settings.database_url_sync,
        settings=settings,
    )
    return {"artifact_id": int(artifact_id)}
