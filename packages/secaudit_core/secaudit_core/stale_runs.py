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
from secaudit_core.enums import AuditFlowStatus
from secaudit_core.models import (
    AagArtifact,
    AuditFlowRun,
    DirectorySync,
    InventoryScan,
    JobRun,
    JobStatus,
    RemediationRun,
)


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


def sweep_stale_inventory_scans(db: Session, cutoff: datetime) -> list[int]:
    scans = db.execute(
        select(InventoryScan).where(
            InventoryScan.status == JobStatus.RUNNING,
            InventoryScan.started_at.isnot(None),
            InventoryScan.started_at < cutoff,
        ).with_for_update(skip_locked=True)
    ).scalars().all()
    now = datetime.now(UTC)
    affected: list[int] = []
    for scan in scans:
        scan.status = JobStatus.FAILED
        scan.error_message = STALE_RUN_ERROR_MESSAGE
        scan.finished_at = now
        affected.append(scan.id)
    return affected


def sweep_stale_directory_syncs(
    db: Session,
    running_cutoff: datetime,
    *,
    pending_cutoff: datetime | None = None,
) -> list[int]:
    """Fail RUNNING and orphan PENDING directory syncs that block new LDAP imports."""
    pending_cutoff = pending_cutoff or running_cutoff
    running = db.execute(
        select(DirectorySync).where(
            DirectorySync.status == JobStatus.RUNNING,
            DirectorySync.started_at.isnot(None),
            DirectorySync.started_at < running_cutoff,
        ).with_for_update(skip_locked=True)
    ).scalars().all()
    pending = db.execute(
        select(DirectorySync).where(
            DirectorySync.status == JobStatus.PENDING,
            DirectorySync.started_at.is_(None),
            DirectorySync.created_at < pending_cutoff,
        ).with_for_update(skip_locked=True)
    ).scalars().all()
    now = datetime.now(UTC)
    affected: list[int] = []
    for sync in (*running, *pending):
        sync.status = JobStatus.FAILED
        sync.error_message = (
            STALE_RUN_ERROR_MESSAGE if sync.started_at is not None else PENDING_ORPHAN_ERROR_MESSAGE
        )
        sync.finished_at = now
        affected.append(sync.id)
    return affected


def sweep_stale_audit_flow_runs(db: Session, cutoff: datetime) -> list[int]:
    runs = db.execute(
        select(AuditFlowRun).where(
            AuditFlowRun.status.in_((AuditFlowStatus.SCANNING, AuditFlowStatus.RUNNING)),
            AuditFlowRun.started_at.isnot(None),
            AuditFlowRun.started_at < cutoff,
        ).with_for_update(skip_locked=True)
    ).scalars().all()
    now = datetime.now(UTC)
    affected: list[int] = []
    for run in runs:
        run.status = AuditFlowStatus.FAILED
        run.error_message = STALE_RUN_ERROR_MESSAGE
        run.finished_at = now
        affected.append(run.id)
    return affected


def sweep_stale_aag_artifacts(db: Session, cutoff: datetime) -> list[int]:
    artifacts = db.execute(
        select(AagArtifact).where(
            AagArtifact.status == "pending",
            AagArtifact.created_at < cutoff,
        ).with_for_update(skip_locked=True)
    ).scalars().all()
    now = datetime.now(UTC)
    affected: list[int] = []
    for artifact in artifacts:
        artifact.status = "failed"
        artifact.error_message = PENDING_ORPHAN_ERROR_MESSAGE
        artifact.finished_at = now
        affected.append(artifact.id)
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
    return {
        "job_runs": sweep_stale_job_runs(db, running_cutoff),
        "remediation_runs": sweep_stale_remediation_runs(db, running_cutoff),
        "pending_job_runs": sweep_orphan_pending_job_runs(db, pending_cutoff),
        "pending_remediation_runs": sweep_orphan_pending_remediation_runs(db, pending_cutoff),
        "inventory_scans": sweep_stale_inventory_scans(db, running_cutoff),
        "directory_syncs": sweep_stale_directory_syncs(
            db, running_cutoff, pending_cutoff=pending_cutoff
        ),
        "audit_flow_runs": sweep_stale_audit_flow_runs(db, running_cutoff),
        "aag_artifacts": sweep_stale_aag_artifacts(db, pending_cutoff),
    }
