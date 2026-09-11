"""Suggest and launch remediation from a completed compliance run."""

from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.auth import AuthUser
from app.models import CheckResult, CheckScript, CheckStatus, ExecutionType, Job, JobRun, JobStatus, ScriptKind, Profile
from app.services.object_rbac import assert_job_run_access


class FailedCheckSummary:
    __slots__ = ("host_id", "rule_tech_name", "status", "message")

    def __init__(self, host_id: int, rule_tech_name: str, status: CheckStatus, message: str | None):
        self.host_id = host_id
        self.rule_tech_name = rule_tech_name
        self.status = status
        self.message = message


async def _load_run_context(db: AsyncSession, user: AuthUser, run_id: int) -> tuple[JobRun, Job]:
    await assert_job_run_access(db, user, run_id)
    result = await db.execute(
        select(JobRun)
        .options(selectinload(JobRun.job).selectinload(Job.profile))
        .where(JobRun.id == run_id)
    )
    run = result.scalar_one_or_none()
    if not run or not run.job:
        raise HTTPException(status_code=404, detail="Job run not found")
    if run.status != JobStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Remediation suggestions require a completed run")
    if not run.job.profile_id:
        raise HTTPException(status_code=400, detail="Job has no profile attached")
    return run, run.job


async def _failed_checks(db: AsyncSession, run_id: int) -> list[FailedCheckSummary]:
    from secaudit_core.waivers import load_active_waivers, waived_fail_ids

    result = await db.execute(select(CheckResult).where(CheckResult.job_run_id == run_id))
    checks = list(result.scalars().all())
    run_result = await db.execute(
        select(JobRun).options(selectinload(JobRun.job)).where(JobRun.id == run_id)
    )
    run = run_result.scalar_one_or_none()
    waived_ids: set[int] = set()
    if run and run.job and run.job.profile_id is not None:
        waivers = await load_active_waivers(db, profile_id=run.job.profile_id, job_id=run.job_id)
        waived_ids = set(
            waived_fail_ids(
                checks,
                waivers,
                profile_id=run.job.profile_id,
                job_id=run.job_id,
            ).keys()
        )
    return [
        FailedCheckSummary(c.host_id, c.rule_tech_name, c.status, c.message)
        for c in checks
        if c.status in (CheckStatus.FAIL, CheckStatus.ERROR) and c.id not in waived_ids
    ]


async def _remediation_scripts(db: AsyncSession, profile_id: int) -> list[CheckScript]:
    result = await db.execute(
        select(CheckScript)
        .where(
            CheckScript.profile_id == profile_id,
            CheckScript.script_kind == ScriptKind.REMEDIATION,
        )
        .order_by(CheckScript.name)
    )
    return list(result.scalars().all())


def _default_execution_type(job: Job, scripts: list[CheckScript]) -> ExecutionType:
    if job.execution_type:
        return job.execution_type
    if scripts:
        return scripts[0].execution_type
    return ExecutionType.SSH


async def build_remediation_suggestion(db: AsyncSession, user: AuthUser, run_id: int) -> dict:
    run, job = await _load_run_context(db, user, run_id)
    failed = await _failed_checks(db, run_id)
    scripts = await _remediation_scripts(db, job.profile_id)
    host_ids = sorted({check.host_id for check in failed})
    profile = job.profile
    profile_name = profile.profile_name if profile else f"Profile #{job.profile_id}"
    default_exec = _default_execution_type(job, scripts)

    return {
        "source_run_id": run_id,
        "source_job_id": job.id,
        "source_job_name": job.name,
        "profile_id": job.profile_id,
        "profile_name": profile_name,
        "host_ids": host_ids,
        "failed_count": len(failed),
        "failed_checks": [
            {
                "host_id": c.host_id,
                "rule_tech_name": c.rule_tech_name,
                "status": c.status,
                "message": c.message,
            }
            for c in failed
        ],
        "remediation_scripts": [
            {
                "id": script.id,
                "name": script.name,
                "execution_type": script.execution_type,
            }
            for script in scripts
        ],
        "suggested_name": f"Remediate — {job.name} (run #{run_id})",
        "default_execution_type": default_exec,
        "default_remediation_script_id": scripts[0].id if scripts else None,
    }
