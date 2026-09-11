import os

from celery.signals import beat_init, worker_process_init
from secaudit_core.celery_redis import create_celery_app
from secaudit_core.security import validate_production_secret_key, validate_production_secrets_backend
from secaudit_core.settings import SecAuditSettings
from secaudit_core.tracing import (
    configure_tracing,
    instrument_celery,
    instrument_http_clients,
    instrument_sqlalchemy,
)


class WorkerSettings(SecAuditSettings):
    pass


settings = WorkerSettings()
validate_production_secret_key(settings.secret_key, settings.app_env)
validate_production_secrets_backend(
    app_env=settings.app_env,
    secrets_backend=settings.secrets_backend,
    secrets_fernet_allowed_in_production=settings.secrets_fernet_allowed_in_production,
    vault_addr=settings.vault_addr,
    vault_token=settings.vault_token,
    vault_token_file=settings.vault_token_file,
    aws_kms_key_id=settings.aws_kms_key_id,
)

celery_app = create_celery_app(
    "secaudit",
    settings,
    include=[
        "app.tasks.compliance",
        "app.tasks.remediation",
        "app.tasks.maintenance",
        "app.tasks.inventory",
        "app.tasks.audit_flow",
        "app.tasks.scheduled_reports",
    ],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    task_soft_time_limit=settings.celery_task_soft_time_limit,
    task_time_limit=settings.celery_task_time_limit,
    task_routes={
        "app.tasks.run_compliance_job": {"queue": "compliance"},
        "app.tasks.compliance.*": {"queue": "compliance"},
        "app.tasks.run_remediation_job": {"queue": "remediation"},
        "app.tasks.remediation.*": {"queue": "remediation"},
        "app.tasks.inventory.*": {"queue": "inventory"},
        "app.tasks.audit_flow.*": {"queue": "inventory"},
        "app.tasks.maintenance.*": {"queue": "maintenance"},
        "app.tasks.scheduled_reports.*": {"queue": "maintenance"},
    },
    beat_schedule={
        "heartbeat-every-minute": {
            "task": "app.tasks.compliance.heartbeat",
            "schedule": 60.0,
            "options": {"queue": "compliance"},
        },
        "run-scheduled-jobs": {
            "task": "app.tasks.compliance.run_scheduled_jobs",
            "schedule": 60.0,
            "options": {"queue": "compliance"},
        },
        "run-scheduled-remediation-jobs": {
            "task": "app.tasks.remediation.run_scheduled_remediation_jobs",
            "schedule": 60.0,
            "options": {"queue": "remediation"},
        },
        "sweep-stale-runs": {
            "task": "app.tasks.maintenance.sweep_stale_runs",
            "schedule": 300.0,
            "options": {"queue": "maintenance"},
        },
        "check-worker-heartbeat": {
            "task": "app.tasks.maintenance.check_worker_heartbeat",
            "schedule": 60.0,
            "options": {"queue": "maintenance"},
        },
        "expire-compliance-waivers": {
            "task": "app.tasks.maintenance.expire_compliance_waivers",
            "schedule": 300.0,
            "options": {"queue": "maintenance"},
        },
        "sync-profiles-catalog": {
            "task": "app.tasks.maintenance.sync_profiles_catalog",
            "schedule": settings.profiles_catalog_sync_interval_seconds,
            "options": {"queue": "maintenance"},
        },
        "dispatch-outbox": {
            "task": "app.tasks.maintenance.dispatch_outbox",
            "schedule": 30.0,
            "options": {"queue": "maintenance"},
        },
        "run-scheduled-reports": {
            "task": "app.tasks.scheduled_reports.run_scheduled_reports",
            "schedule": 60.0,
            "options": {"queue": "maintenance"},
        },
    },
)

def _bootstrap_tracing(service_name: str) -> None:
    if not configure_tracing(service_name, settings=settings):
        return
    instrument_celery(settings=settings)
    instrument_http_clients(settings=settings)
    # Engine is initialised lazily in tasks; instrument the SQLAlchemy library so
    # any engine created afterwards emits spans.
    instrument_sqlalchemy(settings=settings)


@worker_process_init.connect
def _init_worker_tracing(**_kwargs) -> None:
    _bootstrap_tracing("secaudit-worker")


@beat_init.connect
def _init_beat_tracing(**_kwargs) -> None:
    _bootstrap_tracing("secaudit-beat")


# Solo/eager execution (tests, `celery worker --pool=solo`) never fires the
# worker_process_init signal — bootstrap tracing eagerly in that case.
if os.environ.get("CELERY_INIT_TRACING_EAGER") == "1":
    _bootstrap_tracing("secaudit-worker")


import app.observability  # noqa: F401,E402 — register Celery signal handlers
import app.tasks.audit_flow  # noqa: F401,E402 — register AuditFlow scan task
