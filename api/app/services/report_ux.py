"""Report CSV export and multi-run comparison helpers."""

from __future__ import annotations

import csv
import io
from collections.abc import Iterable

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import CheckResult, CheckStatus, Host, JobRun, Rule
from app.schemas import (
    MultiRunCompareCell,
    MultiRunCompareReport,
    MultiRunCompareRow,
    MultiRunCompareRunSummary,
    ReportSummary,
)
from app.services.reports import build_report_summary


def _normalize_severity(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip().lower()
    return cleaned or None


def _csv_escape_row(values: Iterable[object]) -> list[str]:
    out: list[str] = []
    for value in values:
        if value is None:
            out.append("")
        else:
            out.append(str(value))
    return out


async def _severity_by_tech_name(db: AsyncSession, profile_id: int | None) -> dict[str, str]:
    if profile_id is None:
        return {}
    result = await db.execute(select(Rule).where(Rule.profile_id == profile_id))
    mapping: dict[str, str] = {}
    for rule in result.scalars().all():
        severity = _normalize_severity(rule.severity)
        if severity:
            mapping[rule.tech_name] = severity
    return mapping


def render_check_results_csv(
    *,
    run_id: int,
    checks: list[CheckResult],
    hosts: dict[int, Host],
    severity_by_rule: dict[str, str],
    status_filter: str | None = None,
    severity_filter: str | None = None,
    host_id_filter: int | None = None,
    rule_filter: str | None = None,
) -> str:
    status_norm = status_filter.strip().lower() if status_filter else None
    severity_norm = _normalize_severity(severity_filter)
    rule_query = rule_filter.strip().lower() if rule_filter else None

    rows: list[list[str]] = [
        [
            "run_id",
            "host_id",
            "host_name",
            "rule_tech_name",
            "severity",
            "status",
            "message",
            "created_at",
        ]
    ]

    for check in sorted(checks, key=lambda c: (c.host_id, c.rule_tech_name, c.id)):
        status_value = check.status.value if isinstance(check.status, CheckStatus) else str(check.status)
        severity = severity_by_rule.get(check.rule_tech_name)
        if status_norm and status_value.lower() != status_norm:
            continue
        if severity_norm and (severity or "") != severity_norm:
            continue
        if host_id_filter is not None and check.host_id != host_id_filter:
            continue
        if rule_query and rule_query not in check.rule_tech_name.lower():
            continue

        host = hosts.get(check.host_id)
        rows.append(
            _csv_escape_row(
                [
                    run_id,
                    check.host_id,
                    host.name if host else "",
                    check.rule_tech_name,
                    severity or "",
                    status_value,
                    check.message or "",
                    check.created_at.isoformat() if check.created_at else "",
                ]
            )
        )

    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerows(rows)
    return buffer.getvalue()


def render_multi_compare_csv(report: MultiRunCompareReport) -> str:
    header = ["host_id", "rule_tech_name", "severity"]
    for run_id in report.run_ids:
        header.append(f"run_{run_id}_status")
        header.append(f"run_{run_id}_message")

    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(header)

    for row in report.rows:
        cells_by_run = {cell.run_id: cell for cell in row.cells}
        values: list[object] = [row.host_id, row.rule_tech_name, row.severity or ""]
        for run_id in report.run_ids:
            cell = cells_by_run.get(run_id)
            status = ""
            message = ""
            if cell and cell.status is not None:
                status = cell.status.value if isinstance(cell.status, CheckStatus) else str(cell.status)
                message = cell.message or ""
            values.extend([status, message])
        writer.writerow(_csv_escape_row(values))

    return buffer.getvalue()


async def fetch_run_csv(
    db: AsyncSession,
    run_id: int,
    *,
    status: str | None = None,
    severity: str | None = None,
    host_id: int | None = None,
    rule: str | None = None,
) -> tuple[str, str]:
    result = await db.execute(
        select(JobRun)
        .options(selectinload(JobRun.check_results), selectinload(JobRun.job))
        .where(JobRun.id == run_id)
    )
    job_run = result.scalar_one_or_none()
    if not job_run:
        raise HTTPException(status_code=404, detail="Job run not found")

    host_ids = {c.host_id for c in job_run.check_results}
    hosts: dict[int, Host] = {}
    if host_ids:
        hosts_result = await db.execute(select(Host).where(Host.id.in_(host_ids)))
        hosts = {h.id: h for h in hosts_result.scalars().all()}

    profile_id = job_run.job.profile_id if job_run.job else None
    severity_by_rule = await _severity_by_tech_name(db, profile_id)
    content = render_check_results_csv(
        run_id=run_id,
        checks=list(job_run.check_results),
        hosts=hosts,
        severity_by_rule=severity_by_rule,
        status_filter=status,
        severity_filter=severity,
        host_id_filter=host_id,
        rule_filter=rule,
    )
    filename = f"report-{run_id}.csv"
    return content, filename


def build_multi_run_compare(
    *,
    job_id: int,
    runs: list[JobRun],
    checks_by_run: dict[int, list[CheckResult]],
    severity_by_rule: dict[str, str],
) -> MultiRunCompareReport:
    ordered_ids = [run.id for run in runs]
    run_summaries: list[MultiRunCompareRunSummary] = []
    for run in runs:
        summary: ReportSummary = build_report_summary(run.id, checks_by_run.get(run.id, []))
        run_summaries.append(
            MultiRunCompareRunSummary(
                run_id=run.id,
                job_id=run.job_id,
                status=run.status,
                finished_at=run.finished_at,
                compliance_percent=summary.compliance_percent,
                total_checks=summary.total_checks,
                passed=summary.passed,
                failed=summary.failed,
                skipped=summary.skipped,
                errors=summary.errors,
            )
        )

    all_keys: set[tuple[int, str]] = set()
    maps: dict[int, dict[tuple[int, str], CheckResult]] = {}
    for run_id, checks in checks_by_run.items():
        mapping = {(c.host_id, c.rule_tech_name): c for c in checks}
        maps[run_id] = mapping
        all_keys.update(mapping.keys())

    rows: list[MultiRunCompareRow] = []
    for host_id, rule_tech_name in sorted(all_keys):
        cells: list[MultiRunCompareCell] = []
        for run_id in ordered_ids:
            check = maps.get(run_id, {}).get((host_id, rule_tech_name))
            cells.append(
                MultiRunCompareCell(
                    run_id=run_id,
                    status=check.status if check else None,
                    message=(check.message if check and check.message else None),
                )
            )
        rows.append(
            MultiRunCompareRow(
                host_id=host_id,
                rule_tech_name=rule_tech_name,
                severity=severity_by_rule.get(rule_tech_name),
                cells=cells,
            )
        )

    return MultiRunCompareReport(
        job_id=job_id,
        run_ids=ordered_ids,
        runs=run_summaries,
        rows=rows,
    )


async def fetch_multi_run_compare(db: AsyncSession, run_ids: list[int]) -> MultiRunCompareReport:
    unique_ids = list(dict.fromkeys(run_ids))
    if len(unique_ids) < 2:
        raise HTTPException(status_code=400, detail="Select at least two distinct runs to compare")
    if len(unique_ids) > 8:
        raise HTTPException(status_code=400, detail="Compare supports at most 8 runs")

    result = await db.execute(
        select(JobRun).options(selectinload(JobRun.job)).where(JobRun.id.in_(unique_ids))
    )
    found = {run.id: run for run in result.scalars().all()}
    missing = [run_id for run_id in unique_ids if run_id not in found]
    if missing:
        raise HTTPException(status_code=404, detail=f"Job run(s) not found: {missing}")

    runs = [found[run_id] for run_id in unique_ids]
    job_ids = {run.job_id for run in runs}
    if len(job_ids) != 1:
        raise HTTPException(status_code=400, detail="Compared runs must belong to the same job")

    job_id = runs[0].job_id
    checks_by_run: dict[int, list[CheckResult]] = {}
    for run in runs:
        checks_result = await db.execute(select(CheckResult).where(CheckResult.job_run_id == run.id))
        checks_by_run[run.id] = list(checks_result.scalars().all())

    profile_id = runs[0].job.profile_id if runs[0].job else None
    severity_by_rule = await _severity_by_tech_name(db, profile_id)
    return build_multi_run_compare(
        job_id=job_id,
        runs=runs,
        checks_by_run=checks_by_run,
        severity_by_rule=severity_by_rule,
    )


__all__ = [
    "fetch_multi_run_compare",
    "fetch_run_csv",
    "render_check_results_csv",
    "render_multi_compare_csv",
]
