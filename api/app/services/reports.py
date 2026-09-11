from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import CheckResult, Host, Job, JobRun, Profile
from app.schemas import ReportSummary
from secaudit_core.reports import (
    build_report_summary_dict,
    fetch_run_report_context_sync,
    render_run_report_html,
    render_run_report_pdf,
)
from secaudit_core.waivers import load_active_waivers, waived_fail_ids


def build_report_summary(
    run_id: int,
    checks: list,
    *,
    waived_check_ids: set[int] | None = None,
) -> ReportSummary:
    return ReportSummary(**build_report_summary_dict(run_id, checks, waived_check_ids=waived_check_ids))


async def fetch_run_summary(db: AsyncSession, run_id: int) -> ReportSummary:
    result = await db.execute(select(CheckResult).where(CheckResult.job_run_id == run_id))
    checks = list(result.scalars().all())

    run_result = await db.execute(
        select(JobRun).options(selectinload(JobRun.job)).where(JobRun.id == run_id)
    )
    run = run_result.scalar_one_or_none()
    profile_id = run.job.profile_id if run and run.job else None
    job_id = run.job_id if run else None
    waived_ids: set[int] = set()
    if profile_id is not None:
        waivers = await load_active_waivers(db, profile_id=profile_id, job_id=job_id)
        waived_ids = set(
            waived_fail_ids(checks, waivers, profile_id=profile_id, job_id=job_id).keys()
        )
    return build_report_summary(run_id, checks, waived_check_ids=waived_ids)


async def fetch_run_report_context(
    db: AsyncSession, run_id: int
) -> tuple[JobRun, object | None, dict[int, Host]] | None:
    result = await db.execute(
        select(JobRun)
        .options(
            selectinload(JobRun.check_results),
            selectinload(JobRun.job).selectinload(Job.profile).selectinload(Profile.rules),
        )
        .where(JobRun.id == run_id)
    )
    job_run = result.scalar_one_or_none()
    if not job_run:
        return None

    profile = job_run.job.profile if job_run.job else None
    host_ids = {c.host_id for c in job_run.check_results}
    hosts_result = await db.execute(select(Host).where(Host.id.in_(host_ids)))
    hosts = {h.id: h for h in hosts_result.scalars().all()}
    return job_run, profile, hosts


__all__ = [
    "build_report_summary",
    "fetch_run_report_context",
    "fetch_run_report_context_sync",
    "fetch_run_summary",
    "render_run_report_html",
    "render_run_report_pdf",
]
