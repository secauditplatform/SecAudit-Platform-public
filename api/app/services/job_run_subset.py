"""Build a partial job run from a previous run's host outcomes."""

from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.auth import AuthUser
from app.models import Job, JobRun, JobStatus
from app.services.object_rbac import assert_can_access
from secaudit_core.job_run_subset import (
    SubsetKind,
    classify_host_outcomes,
    resolve_subset_host_ids,
)

_TERMINAL = frozenset(
    {JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED}
)


async def load_source_run(db: AsyncSession, user: AuthUser, run_id: int) -> tuple[JobRun, Job]:
    result = await db.execute(
        select(JobRun)
        .options(selectinload(JobRun.job), selectinload(JobRun.check_results))
        .where(JobRun.id == run_id)
    )
    run = result.scalar_one_or_none()
    if not run or not run.job:
        raise HTTPException(status_code=404, detail="Job run not found")
    assert_can_access(user, run.job.owner_sub, detail="Job run not found")
    if run.status not in _TERMINAL:
        raise HTTPException(
            status_code=400,
            detail="Restart requires a finished run (completed, failed, or cancelled)",
        )
    return run, run.job


async def preview_rerun_targets(db: AsyncSession, user: AuthUser, run_id: int) -> dict:
    run, _job = await load_source_run(db, user, run_id)
    classified = classify_host_outcomes(run.check_results or [])
    stored = [int(host_id) for host_id in (run.host_ids or []) if host_id is not None]
    return {
        "source_run_id": run.id,
        "is_partial": bool(run.is_partial),
        "host_ids": stored or classified["all"],
        "failed_host_ids": classified["failed"],
        "skipped_host_ids": classified["skipped"],
    }


def choose_rerun_hosts(
    source: JobRun,
    *,
    subset: SubsetKind,
    host_ids: list[int] | None,
) -> list[int]:
    classified = classify_host_outcomes(source.check_results or [])
    allowed = set(classified["all"])
    if source.host_ids:
        allowed |= {int(host_id) for host_id in source.host_ids if host_id is not None}
    try:
        return resolve_subset_host_ids(
            subset=subset,
            classified=classified,
            selected_host_ids=host_ids,
            allowed_host_ids=allowed,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


async def create_subset_run(
    db: AsyncSession,
    *,
    job: Job,
    source: JobRun,
    subset: SubsetKind,
    host_ids: list[int] | None,
) -> JobRun:
    if subset == "all":
        return JobRun(
            job_id=job.id,
            status=JobStatus.PENDING,
            is_partial=False,
            source_run_id=source.id,
        )

    chosen = choose_rerun_hosts(source, subset=subset, host_ids=host_ids)
    return JobRun(
        job_id=job.id,
        status=JobStatus.PENDING,
        host_ids=chosen,
        is_partial=True,
        subset_kind=subset,
        source_run_id=source.id,
    )
