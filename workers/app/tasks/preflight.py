"""Celery tasks for host/credential pre-flight probes."""

from __future__ import annotations

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.celery_app import celery_app, settings
from app.preflight_probe import probe_host_record

engine = create_engine(settings.database_url_sync)
SessionLocal = sessionmaker(bind=engine)


@celery_app.task(name="app.tasks.preflight.probe_host", soft_time_limit=30, time_limit=40)
def probe_host(host_id: int, credential_id: int | None = None) -> dict:
    with SessionLocal() as db:
        return probe_host_record(db, host_id, credential_id, settings)
