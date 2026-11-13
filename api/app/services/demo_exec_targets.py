"""Enforce DEMO_EXEC_ALLOWED_CIDRS for demo-stand remote execution."""

from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import Host, Job, JobHost, RemediationJob, RemediationJobHost
from secaudit_core.demo_exec_guard import DemoExecTargetError, assert_hostnames_in_demo_cidrs
from secaudit_core.hosts import resolve_job_targets


def _raise_demo_target_error(exc: DemoExecTargetError) -> None:
    raise HTTPException(status_code=403, detail=str(exc)) from exc


async def assert_demo_exec_host_ids(db: AsyncSession, host_ids: list[int]) -> None:
    if not settings.demo_mode or not host_ids:
        return
    unique_ids = list(dict.fromkeys(int(host_id) for host_id in host_ids))
    result = await db.execute(select(Host.id, Host.hostname).where(Host.id.in_(unique_ids)))
    rows = result.all()
    if len(rows) != len(unique_ids):
        raise HTTPException(status_code=404, detail="Host not found")
    try:
        assert_hostnames_in_demo_cidrs(
            [hostname for _host_id, hostname in rows if hostname],
            allowed_cidrs_raw=settings.demo_exec_allowed_cidrs,
        )
    except DemoExecTargetError as exc:
        _raise_demo_target_error(exc)


async def assert_demo_exec_job(db: AsyncSession, job: Job) -> None:
    if not settings.demo_mode:
        return

    result = await db.execute(select(JobHost.host_id).where(JobHost.job_id == job.id))
    host_ids = [int(row[0]) for row in result.all()]
    if host_ids:
        await assert_demo_exec_host_ids(db, host_ids)
        return

    def _resolve(sync_db: Session) -> list[int]:
        return resolve_job_targets(
            sync_db,
            job.id,
            job.dynamic_filter,
            owner_sub=job.owner_sub,
            enforce_owner_scope=True,
        )

    host_ids = await db.run_sync(_resolve)
    await assert_demo_exec_host_ids(db, host_ids)


async def assert_demo_exec_remediation_job(db: AsyncSession, job: RemediationJob) -> None:
    if not settings.demo_mode:
        return
    result = await db.execute(
        select(RemediationJobHost.host_id).where(RemediationJobHost.remediation_job_id == job.id)
    )
    await assert_demo_exec_host_ids(db, [int(row[0]) for row in result.all()])
