"""Apply Redis Sentinel transport options to Celery configuration."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from celery import Celery
    from secaudit_core.settings import SecAuditSettings


def prepare_celery_redis_env(settings: SecAuditSettings) -> None:
    """Sync Celery env vars with effective broker/backend URLs.

    Celery reads ``CELERY_BROKER_URL`` / ``CELERY_RESULT_BACKEND`` from the
    environment at runtime and overrides programmatic config. In Sentinel mode
    the logical ``redis://master-name/DB`` URLs must be replaced with
    ``sentinel://`` endpoints before the Celery app connects.
    """
    os.environ["CELERY_BROKER_URL"] = settings.celery_broker_url_effective
    os.environ["CELERY_RESULT_BACKEND"] = settings.celery_result_backend_effective


def apply_celery_redis_config(conf, settings: SecAuditSettings) -> None:
    """Configure Celery broker/backend for standalone or Sentinel Redis."""
    prepare_celery_redis_env(settings)
    conf.broker_url = settings.celery_broker_url_effective
    conf.result_backend = settings.celery_result_backend_effective
    transport = settings.celery_transport_options()
    if not transport:
        return
    conf.broker_transport_options = transport
    conf.result_backend_transport_options = dict(transport)


def create_celery_app(
    name: str,
    settings: SecAuditSettings,
    *,
    include: list[str] | None = None,
) -> Celery:
    from celery import Celery

    prepare_celery_redis_env(settings)
    app = Celery(
        name,
        broker=settings.celery_broker_url_effective,
        backend=settings.celery_result_backend_effective,
        include=include,
    )
    from secaudit_core.celery_task import SecAuditTask

    app.Task = SecAuditTask
    apply_celery_redis_config(app.conf, settings)
    return app
