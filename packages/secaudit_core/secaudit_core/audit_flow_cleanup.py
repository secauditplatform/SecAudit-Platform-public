"""Expire old AuditFlow runs outside of request handlers."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session, selectinload

from secaudit_core.audit_flow_present import job_run_ids_for_host
from secaudit_core.models import (
    AuditFlowRun,
    CheckResult,
    ComplianceWaiver,
    Credential,
    Host,
    HostTagLink,
    InventoryScanResult,
    Job,
    JobHost,
    JobRun,
    JobTemplateHost,
    RemediationJobHost,
    RemediationResult,
)

TTL = timedelta(hours=24)
_AF_EPHEMERAL_DESCRIPTIONS = frozenset({"AuditFlow ephemeral", "AuditFlow inventory"})


def _is_durable_catalog_credential(cred: Credential | None) -> bool:
    if cred is None:
        return False
    if getattr(cred, "is_ephemeral", None) is not False:
        return False
    return (getattr(cred, "description", None) or "") not in _AF_EPHEMERAL_DESCRIPTIONS


def _cleanup_ephemeral_host_refs(db: Session, host_id: int) -> None:
    db.execute(delete(CheckResult).where(CheckResult.host_id == host_id))
    db.execute(delete(RemediationResult).where(RemediationResult.host_id == host_id))
    db.execute(delete(JobHost).where(JobHost.host_id == host_id))
    db.execute(delete(RemediationJobHost).where(RemediationJobHost.host_id == host_id))
    db.execute(delete(JobTemplateHost).where(JobTemplateHost.host_id == host_id))
    db.execute(delete(HostTagLink).where(HostTagLink.host_id == host_id))
    db.execute(update(ComplianceWaiver).where(ComplianceWaiver.host_id == host_id).values(host_id=None))
    db.execute(
        update(InventoryScanResult).where(InventoryScanResult.host_id == host_id).values(host_id=None)
    )


def _delete_ephemeral_credentials(db: Session, cred_ids: list[int]) -> None:
    unique_ids = list(dict.fromkeys(cred_ids))
    if not unique_ids:
        return
    db.execute(update(Host).where(Host.credential_id.in_(unique_ids)).values(credential_id=None))
    db.flush()
    for cred_id in unique_ids:
        cred = db.get(Credential, cred_id)
        if cred is None or _is_durable_catalog_credential(cred):
            continue
        db.delete(cred)


def delete_run_artifacts_sync(db: Session, run: AuditFlowRun) -> None:
    loaded = db.execute(
        select(AuditFlowRun)
        .options(selectinload(AuditFlowRun.hosts), selectinload(AuditFlowRun.credentials))
        .where(AuditFlowRun.id == run.id)
    ).scalar_one_or_none()
    if loaded is None:
        return

    job_run_ids = list(dict.fromkeys(id_ for row in loaded.hosts for id_ in job_run_ids_for_host(row)))
    host_ids = [h.ephemeral_host_id for h in loaded.hosts if h.ephemeral_host_id]
    cred_ids = [h.ephemeral_credential_id for h in loaded.hosts if h.ephemeral_credential_id]

    for row in loaded.hosts:
        row.job_run_id = None
        row.ephemeral_host_id = None
        row.ephemeral_credential_id = None
        row.extra_runs_json = None
    db.flush()

    job_ids: list[int] = []
    if job_run_ids:
        job_ids = list(
            {
                job_id
                for (job_id,) in db.execute(select(JobRun.job_id).where(JobRun.id.in_(job_run_ids))).all()
                if job_id is not None
            }
        )
        db.execute(delete(CheckResult).where(CheckResult.job_run_id.in_(job_run_ids)))
        db.execute(delete(JobRun).where(JobRun.id.in_(job_run_ids)))

    if job_ids:
        leftover = {
            job_id
            for (job_id,) in db.execute(select(JobRun.job_id).where(JobRun.job_id.in_(job_ids))).all()
        }
        drop_jobs = [job_id for job_id in job_ids if job_id not in leftover]
        if drop_jobs:
            db.execute(
                update(ComplianceWaiver).where(ComplianceWaiver.job_id.in_(drop_jobs)).values(job_id=None)
            )
            db.execute(delete(JobHost).where(JobHost.job_id.in_(drop_jobs)))
            db.execute(delete(Job).where(Job.id.in_(drop_jobs)))

    ephemeral_ids: list[int] = []
    if host_ids:
        ephemeral_ids = list(
            db.execute(select(Host.id).where(Host.id.in_(host_ids), Host.is_ephemeral.is_(True)))
            .scalars()
            .all()
        )
    for host_id in ephemeral_ids:
        _cleanup_ephemeral_host_refs(db, host_id)
        host = db.get(Host, host_id)
        if host:
            db.delete(host)
    db.flush()

    if cred_ids:
        _delete_ephemeral_credentials(db, cred_ids)


def sweep_orphaned_ephemeral_credentials_sync(db: Session) -> int:
    rows = list(db.execute(select(Credential).where(Credential.is_ephemeral.is_(True))).scalars().all())
    deleted = 0
    for cred in rows:
        if _is_durable_catalog_credential(cred):
            continue
        still_used = db.execute(
            select(Host.id).where(Host.credential_id == cred.id).limit(1)
        ).scalar_one_or_none()
        if still_used is not None:
            continue
        db.delete(cred)
        deleted += 1
    return deleted


def cleanup_expired_audit_flow_runs(db: Session, *, limit: int = 20) -> dict:
    cutoff = datetime.now(UTC) - TTL
    runs = list(
        db.execute(select(AuditFlowRun).where(AuditFlowRun.created_at < cutoff).limit(limit))
        .scalars()
        .all()
    )
    deleted_ids: list[int] = []
    for run in runs:
        delete_run_artifacts_sync(db, run)
        deleted_ids.append(run.id)
        db.delete(run)
    orphans = sweep_orphaned_ephemeral_credentials_sync(db)
    db.commit()
    return {"deleted_runs": deleted_ids, "count": len(deleted_ids), "orphaned_credentials": orphans}
