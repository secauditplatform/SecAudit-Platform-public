"""Purge terminal JobRuns older than the configured retention window."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import and_, delete, or_, select, update
from sqlalchemy.orm import Session

from secaudit_core.enums import JobStatus
from secaudit_core.models import AuditLog, CheckResult, Job, JobRun, RemediationJob

TERMINAL_STATUSES = (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED)
DEFAULT_BATCH_SIZE = 200


def _protected_run_ids(db: Session) -> set[int]:
    protected: set[int] = set()
    for (run_id,) in db.execute(
        select(Job.baseline_run_id).where(Job.baseline_run_id.is_not(None))
    ):
        if run_id is not None:
            protected.add(int(run_id))

    for col in (RemediationJob.source_run_id, RemediationJob.workflow_reaudit_run_id):
        for (run_id,) in db.execute(select(col).where(col.is_not(None))):
            protected.add(int(run_id))

    # shortcut: ComplianceWaiver has no citations_json (only AAG artifacts do), so waivers
    # protect no extra runs; revisit if waivers gain run citations.
    return protected


def purge_old_job_runs(
    db: Session,
    *,
    retention_days: int,
    limit: int = DEFAULT_BATCH_SIZE,
) -> dict:
    """Delete whole JobRuns past retention, except baseline / remediation-linked runs."""
    days = int(retention_days)
    if days <= 0:
        return {"skipped": True, "reason": "retention_disabled", "deleted": [], "count": 0}

    cutoff = datetime.now(UTC) - timedelta(days=days)
    protected = _protected_run_ids(db)

    stmt = (
        select(JobRun.id)
        .where(
            JobRun.status.in_(TERMINAL_STATUSES),
            or_(
                and_(JobRun.finished_at.is_not(None), JobRun.finished_at < cutoff),
                and_(JobRun.finished_at.is_(None), JobRun.created_at < cutoff),
            ),
        )
        .order_by(JobRun.id.asc())
        .limit(max(1, int(limit)))
    )
    candidate_ids = [int(run_id) for (run_id,) in db.execute(stmt)]
    delete_ids = [run_id for run_id in candidate_ids if run_id not in protected]
    if not delete_ids:
        return {
            "skipped": False,
            "deleted": [],
            "count": 0,
            "cutoff": cutoff.isoformat(),
            "protected_skipped": len(candidate_ids),
        }

    # Clear self-FK pointers that would block delete (SET NULL is on DB, but be explicit).
    db.execute(
        update(JobRun)
        .where(JobRun.source_run_id.in_(delete_ids))
        .values(source_run_id=None)
    )
    db.execute(delete(CheckResult).where(CheckResult.job_run_id.in_(delete_ids)))
    db.execute(delete(JobRun).where(JobRun.id.in_(delete_ids)))

    db.add(
        AuditLog(
            actor_username="system:maintenance",
            actor_roles=["system"],
            action="job_run.purge",
            resource_type="job_run",
            resource_id=None,
            resource_name=f"purged {len(delete_ids)} run(s)",
            outcome="success",
            metadata_json={
                "retention_days": days,
                "cutoff": cutoff.isoformat(),
                "deleted_ids": delete_ids,
                "count": len(delete_ids),
                "protected_skipped": len(candidate_ids) - len(delete_ids),
            },
        )
    )
    db.commit()
    return {
        "skipped": False,
        "deleted": delete_ids,
        "count": len(delete_ids),
        "cutoff": cutoff.isoformat(),
        "protected_skipped": len(candidate_ids) - len(delete_ids),
    }


def archive_check_raw_output(
    db: Session,
    *,
    retention_days: int,
    limit: int = 2000,
) -> dict:
    """Null raw_output on check rows older than retention_days.

    shortcut: not a monthly partition of check_results. PostgreSQL requires the
    partition key in every unique constraint, and uq_check_result_run_host_rule
    omits created_at, so partitioning would break ON CONFLICT upserts. Upgrade
    only if upserts no longer depend on that key.
    """
    days = int(retention_days)
    if days <= 0:
        return {"skipped": True, "reason": "retention_disabled", "cleared": 0}

    cutoff = datetime.now(UTC) - timedelta(days=days)
    ids = [
        int(row_id)
        for (row_id,) in db.execute(
            select(CheckResult.id)
            .where(CheckResult.raw_output.is_not(None), CheckResult.created_at < cutoff)
            .order_by(CheckResult.id.asc())
            .limit(max(1, int(limit)))
        )
    ]
    if not ids:
        return {"skipped": False, "cleared": 0, "cutoff": cutoff.isoformat()}

    db.execute(update(CheckResult).where(CheckResult.id.in_(ids)).values(raw_output=None))
    db.add(
        AuditLog(
            actor_username="system:maintenance",
            actor_roles=["system"],
            action="check_result.archive_raw_output",
            resource_type="check_result",
            resource_id=None,
            resource_name=f"cleared raw_output on {len(ids)} check(s)",
            outcome="success",
            metadata_json={"retention_days": days, "cutoff": cutoff.isoformat(), "cleared": len(ids)},
        )
    )
    db.commit()
    return {"skipped": False, "cleared": len(ids), "cutoff": cutoff.isoformat()}
