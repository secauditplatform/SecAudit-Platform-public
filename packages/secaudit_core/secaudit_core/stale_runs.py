"""Mark stale RUNNING job/remediation runs as FAILED."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from secaudit_core.celery_reliability import (
    PENDING_ORPHAN_ERROR_MESSAGE,
    STALE_RUN_ERROR_MESSAGE,
    WORKER_LOST_ERROR_MESSAGE,
)
from secaudit_core.models import JobRun, JobStatus, RemediationRun


def sweep_stale_job_runs(db: Session, cutoff: datetime) -> list[int]:
    """Mark JobRuns stuck in RUNNING before cutoff as FAILED. Returns affected ids."""
    runs = db.execute(
        select(JobRun).where(
            JobRun.status == JobStatus.RUNNING,
            JobRun.started_at.isnot(None),
            JobRun.started_at < cutoff,
        ).with_for_update(skip_locked=True)
    ).scalars().all()
    now = datetime.now(UTC)
    affected: list[int] = []
    for run in runs:
        run.status = JobStatus.FAILED
        run.error_message = STALE_RUN_ERROR_MESSAGE
        run.finished_at = now
        affected.append(run.id)
    return affected


def sweep_stale_remediation_runs(db: Session, cutoff: datetime) -> list[int]:
    """Mark RemediationRuns stuck in RUNNING before cutoff as FAILED. Returns affected ids."""
    runs = db.execute(
        select(RemediationRun).where(
            RemediationRun.status == JobStatus.RUNNING,
            RemediationRun.started_at.isnot(None),
            RemediationRun.started_at < cutoff,
        ).with_for_update(skip_locked=True)
    ).scalars().all()
    now = datetime.now(UTC)
    affected: list[int] = []
    for run in runs:
        run.status = JobStatus.FAILED
        run.error_message = STALE_RUN_ERROR_MESSAGE
        run.finished_at = now
        affected.append(run.id)
    return affected


def sweep_orphan_pending_job_runs(db: Session, cutoff: datetime) -> list[int]:
    """Mark JobRuns stuck in PENDING before cutoff as FAILED. Returns affected ids."""
    runs = db.execute(
        select(JobRun).where(
            JobRun.status == JobStatus.PENDING,
            JobRun.started_at.is_(None),
            JobRun.created_at < cutoff,
        ).with_for_update(skip_locked=True)
    ).scalars().all()
    now = datetime.now(UTC)
    affected: list[int] = []
    for run in runs:
        run.status = JobStatus.FAILED
        run.error_message = PENDING_ORPHAN_ERROR_MESSAGE
        run.finished_at = now
        affected.append(run.id)
    return affected


def sweep_orphan_pending_remediation_runs(db: Session, cutoff: datetime) -> list[int]:
    """Mark RemediationRuns stuck in PENDING before cutoff as FAILED. Returns affected ids."""
    runs = db.execute(
        select(RemediationRun).where(
            RemediationRun.status == JobStatus.PENDING,
            RemediationRun.started_at.is_(None),
            RemediationRun.created_at < cutoff,
        ).with_for_update(skip_locked=True)
    ).scalars().all()
    now = datetime.now(UTC)
    affected: list[int] = []
    for run in runs:
        run.status = JobStatus.FAILED
        run.error_message = PENDING_ORPHAN_ERROR_MESSAGE
        run.finished_at = now
        affected.append(run.id)
    return affected


def _sweep_worker_lost_runs(
    db: Session,
    model: type[JobRun] | type[RemediationRun],
    *,
    active_task_ids: set[str],
    grace: timedelta,
) -> list[int]:
    """Fail RUNNING runs whose Celery task is no longer active on any worker."""
    cutoff = datetime.now(UTC) - grace
    runs = db.execute(
        select(model).where(
            model.status == JobStatus.RUNNING,
            model.started_at.isnot(None),
            model.started_at < cutoff,
            model.celery_task_id.isnot(None),
        ).with_for_update(skip_locked=True)
    ).scalars().all()
    now = datetime.now(UTC)
    affected: list[int] = []
    for run in runs:
        if run.celery_task_id in active_task_ids:
            continue
        run.status = JobStatus.FAILED
        run.error_message = WORKER_LOST_ERROR_MESSAGE
        run.finished_at = now
        affected.append(run.id)
    return affected


def reconcile_worker_lost_runs(
    db: Session,
    active_task_ids: set[str],
    *,
    grace: timedelta | None = None,
) -> dict[str, list[int]]:
    grace = grace or timedelta(minutes=3)
    return {
        "job_runs": _sweep_worker_lost_runs(
            db, JobRun, active_task_ids=active_task_ids, grace=grace
        ),
        "remediation_runs": _sweep_worker_lost_runs(
            db, RemediationRun, active_task_ids=active_task_ids, grace=grace
        ),
    }


def sweep_stale_runs(
    db: Session,
    running_cutoff: datetime,
    *,
    pending_cutoff: datetime | None = None,
) -> dict[str, list[int]]:
    """Sweep RUNNING and orphan PENDING runs. Returns ids grouped by kind."""
    pending_cutoff = pending_cutoff or running_cutoff
    job_ids = sweep_stale_job_runs(db, running_cutoff)
    remediation_ids = sweep_stale_remediation_runs(db, running_cutoff)
    pending_job_ids = sweep_orphan_pending_job_runs(db, pending_cutoff)
    pending_remediation_ids = sweep_orphan_pending_remediation_runs(db, pending_cutoff)
    return {
        "job_runs": job_ids,
        "remediation_runs": remediation_ids,
        "pending_job_runs": pending_job_ids,
        "pending_remediation_runs": pending_remediation_ids,
    }
