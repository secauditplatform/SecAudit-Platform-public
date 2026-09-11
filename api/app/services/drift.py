from typing import Literal

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import CheckResult, CheckStatus, Job, JobRun, JobStatus
from app.schemas import DiffReport, DiffRow, DiffSummary, DriftItem, DriftReport, DriftSummary
from app.services.reports import build_report_summary

DriftChange = Literal["improved", "regressed", "unchanged", "new", "removed"]


def _is_pass(status: CheckStatus) -> bool:
    return status == CheckStatus.PASS


def _is_fail_or_error(status: CheckStatus) -> bool:
    return status in (CheckStatus.FAIL, CheckStatus.ERROR)


def classify_drift_change(
    baseline_status: CheckStatus | None, current_status: CheckStatus | None
) -> DriftChange:
    if baseline_status is None:
        return "new"
    if current_status is None:
        return "removed"
    if baseline_status == current_status:
        return "unchanged"
    if _is_fail_or_error(baseline_status) and _is_pass(current_status):
        return "improved"
    if _is_pass(baseline_status) and _is_fail_or_error(current_status):
        return "regressed"
    return "unchanged"


def _check_status(check) -> CheckStatus | None:
    return None if check is None else check.status


def _check_message(check) -> str | None:
    if check is None:
        return None
    message = getattr(check, "message", None)
    return message if message else None


def compare_check_results(
    current_run_id: int,
    baseline_run_id: int,
    baseline_checks: list,
    current_checks: list,
) -> DriftReport:
    baseline_map = {(c.host_id, c.rule_tech_name): c for c in baseline_checks}
    current_map = {(c.host_id, c.rule_tech_name): c for c in current_checks}
    all_keys = set(baseline_map.keys()) | set(current_map.keys())

    items: list[DriftItem] = []
    counts = {"improved": 0, "regressed": 0, "unchanged": 0, "new": 0, "removed": 0}

    for host_id, rule_tech_name in sorted(all_keys):
        baseline_check = baseline_map.get((host_id, rule_tech_name))
        current_check = current_map.get((host_id, rule_tech_name))
        baseline_status = _check_status(baseline_check)
        current_status = _check_status(current_check)
        change = classify_drift_change(baseline_status, current_status)
        counts[change] += 1
        items.append(
            DriftItem(
                host_id=host_id,
                rule_tech_name=rule_tech_name,
                baseline_status=baseline_status,
                current_status=current_status,
                baseline_message=_check_message(baseline_check),
                current_message=_check_message(current_check),
                change=change,
            )
        )

    baseline_summary = build_report_summary(baseline_run_id, baseline_checks)
    current_summary = build_report_summary(current_run_id, current_checks)
    compliance_delta = round(
        current_summary.compliance_percent - baseline_summary.compliance_percent, 2
    )

    summary = DriftSummary(
        current_run_id=current_run_id,
        baseline_run_id=baseline_run_id,
        improved=counts["improved"],
        regressed=counts["regressed"],
        unchanged=counts["unchanged"],
        new=counts["new"],
        removed=counts["removed"],
        baseline_compliance_percent=baseline_summary.compliance_percent,
        current_compliance_percent=current_summary.compliance_percent,
        compliance_delta=compliance_delta,
    )
    return DriftReport(summary=summary, items=items)


def drift_report_to_diff(drift: DriftReport) -> DiffReport:
    """Map drift (baseline→current) to side-by-side Diff (left=baseline, right=current)."""
    summary = DiffSummary(
        left_run_id=drift.summary.baseline_run_id,
        right_run_id=drift.summary.current_run_id,
        improved=drift.summary.improved,
        regressed=drift.summary.regressed,
        unchanged=drift.summary.unchanged,
        new=drift.summary.new,
        removed=drift.summary.removed,
        left_compliance_percent=drift.summary.baseline_compliance_percent,
        right_compliance_percent=drift.summary.current_compliance_percent,
        compliance_delta=drift.summary.compliance_delta,
    )
    items = [
        DiffRow(
            key=f"{item.host_id}:{item.rule_tech_name}",
            host_id=item.host_id,
            rule_tech_name=item.rule_tech_name,
            left_status=item.baseline_status,
            right_status=item.current_status,
            left_message=item.baseline_message,
            right_message=item.current_message,
            change=item.change,
        )
        for item in drift.items
    ]
    return DiffReport(summary=summary, items=items)


async def fetch_diff_report(db: AsyncSession, left_run_id: int, right_run_id: int) -> DiffReport:
    """Side-by-side compare: left = run A, right = run B (reuses drift pairing)."""
    drift = await fetch_drift_report(db, right_run_id, left_run_id)
    return drift_report_to_diff(drift)


async def _fetch_run_checks(db: AsyncSession, run_id: int) -> list[CheckResult]:
    result = await db.execute(select(CheckResult).where(CheckResult.job_run_id == run_id))
    return list(result.scalars().all())


async def _get_job_run(db: AsyncSession, run_id: int) -> JobRun | None:
    return await db.get(JobRun, run_id)


async def fetch_drift_report(
    db: AsyncSession, current_run_id: int, baseline_run_id: int
) -> DriftReport:
    if current_run_id == baseline_run_id:
        raise HTTPException(status_code=400, detail="Cannot compare a run to itself")

    current_run = await _get_job_run(db, current_run_id)
    if not current_run:
        raise HTTPException(status_code=404, detail="Current job run not found")

    baseline_run = await _get_job_run(db, baseline_run_id)
    if not baseline_run:
        raise HTTPException(status_code=404, detail="Baseline job run not found")

    if current_run.job_id != baseline_run.job_id:
        raise HTTPException(status_code=404, detail="Runs belong to different jobs")

    baseline_checks = await _fetch_run_checks(db, baseline_run_id)
    current_checks = await _fetch_run_checks(db, current_run_id)
    return compare_check_results(
        current_run_id, baseline_run_id, baseline_checks, current_checks
    )


async def get_job_baseline_run_id(db: AsyncSession, job_id: int) -> int | None:
    job = await db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job.baseline_run_id


async def set_job_baseline(db: AsyncSession, job_id: int, run_id: int) -> int:
    job = await db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    run = await _get_job_run(db, run_id)
    if not run or run.job_id != job_id:
        raise HTTPException(status_code=404, detail="Run not found for this job")
    if run.status != JobStatus.COMPLETED:
        raise HTTPException(status_code=400, detail="Only completed runs can be set as baseline")

    job.baseline_run_id = run_id
    await db.commit()
    return run_id


async def clear_job_baseline(db: AsyncSession, job_id: int) -> None:
    job = await db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    job.baseline_run_id = None
    await db.commit()
