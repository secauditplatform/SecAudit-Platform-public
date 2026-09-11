from collections import defaultdict
from datetime import UTC, date, datetime, timedelta

from sqlalchemy import and_, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import CheckResult, CheckStatus, ComplianceWaiver, Host, Job, JobRun, JobStatus, Profile, WaiverStatus
from app.schemas import (
    ComplianceBandPoint,
    ComplianceOpsKpis,
    ComplianceOpsOverview,
    ComplianceTimelinePoint,
    DailyOpsPoint,
    HostCompliancePoint,
    JobOpsPoint,
    PlatformOpsPoint,
    ProfileCompliancePoint,
    RuleFailPoint,
    StatusCountPoint,
    WeekdayHeatCell,
)
from app.services.object_rbac import apply_owner_scope
from app.services.reports import build_report_summary


def resolve_period(
    *,
    days: int = 30,
    date_from: date | None = None,
    date_to: date | None = None,
) -> tuple[datetime, datetime, int]:
    now = datetime.now(UTC)
    if date_from is None and date_to is None:
        return now - timedelta(days=days), now, days

    end_date = date_to or date_from or now.date()
    start_date = date_from or end_date
    if start_date > end_date:
        start_date, end_date = end_date, start_date

    start = datetime.combine(start_date, datetime.min.time(), tzinfo=UTC)
    end = datetime.combine(end_date + timedelta(days=1), datetime.min.time(), tzinfo=UTC) - timedelta(microseconds=1)
    if end > now:
        end = now
    span_days = max(1, (end_date - start_date).days + 1)
    return start, end, span_days


def build_timeline_points(runs: list, checks_by_run: dict[int, list]) -> list[ComplianceTimelinePoint]:
    points: list[ComplianceTimelinePoint] = []
    for run in runs:
        checks = checks_by_run.get(run.id, [])
        summary = build_report_summary(run.id, checks)
        job_name = run.job.name if run.job else f"Job #{run.job_id}"
        points.append(
            ComplianceTimelinePoint(
                run_id=run.id,
                job_id=run.job_id,
                job_name=job_name,
                finished_at=run.finished_at,
                compliance_percent=summary.compliance_percent,
                passed=summary.passed,
                failed=summary.failed,
                total_checks=summary.total_checks,
            )
        )
    return points


def aggregate_checks_by_host(checks: list, host_names: dict[int, str]) -> list[HostCompliancePoint]:
    by_host: dict[int, list] = defaultdict(list)
    for check in checks:
        by_host[check.host_id].append(check)

    points: list[HostCompliancePoint] = []
    for host_id in sorted(by_host.keys()):
        host_checks = by_host[host_id]
        summary = build_report_summary(0, host_checks)
        points.append(
            HostCompliancePoint(
                host_id=host_id,
                host_name=host_names.get(host_id, f"host#{host_id}"),
                compliance_percent=summary.compliance_percent,
                passed=summary.passed,
                failed=summary.failed,
                total_checks=summary.total_checks,
            )
        )
    return points


def aggregate_profile_compliance(
    runs: list,
    checks_by_run: dict[int, list],
    profiles: dict[int, Profile],
) -> list[ProfileCompliancePoint]:
    by_profile: dict[int, list[tuple[JobRun, float]]] = defaultdict(list)

    for run in runs:
        job = run.job
        if job is None or job.profile_id is None:
            continue
        summary = build_report_summary(run.id, checks_by_run.get(run.id, []))
        by_profile[job.profile_id].append((run, summary.compliance_percent))

    points: list[ProfileCompliancePoint] = []
    for profile_id in sorted(by_profile.keys()):
        entries = by_profile[profile_id]
        avg = round(sum(pct for _, pct in entries) / len(entries), 2)
        latest_run = max(entries, key=lambda item: item[0].finished_at or datetime.min.replace(tzinfo=UTC))[0]
        profile = profiles.get(profile_id)
        profile_name = profile.profile_name if profile else f"Profile #{profile_id}"
        points.append(
            ProfileCompliancePoint(
                profile_id=profile_id,
                profile_name=profile_name,
                job_count=len(entries),
                avg_compliance_percent=avg,
                latest_run_id=latest_run.id,
            )
        )
    return points


async def _fetch_checks_by_run(db: AsyncSession, run_ids: list[int]) -> dict[int, list]:
    if not run_ids:
        return {}
    result = await db.execute(select(CheckResult).where(CheckResult.job_run_id.in_(run_ids)))
    checks_by_run: dict[int, list] = defaultdict(list)
    for check in result.scalars().all():
        checks_by_run[check.job_run_id].append(check)
    return checks_by_run


async def fetch_compliance_timeline(
    db: AsyncSession,
    job_id: int | None,
    profile_id: int | None,
    days: int = 30,
    limit: int = 50,
    user=None,
    date_from: date | None = None,
    date_to: date | None = None,
) -> list[ComplianceTimelinePoint]:
    start, end, _span = resolve_period(days=days, date_from=date_from, date_to=date_to)
    stmt = (
        select(JobRun)
        .join(Job, JobRun.job_id == Job.id)
        .options(selectinload(JobRun.job))
        .where(
            JobRun.status == JobStatus.COMPLETED,
            JobRun.finished_at.isnot(None),
            JobRun.finished_at >= start,
            JobRun.finished_at <= end,
        )
        .order_by(JobRun.finished_at.asc())
        .limit(limit)
    )
    if job_id is not None:
        stmt = stmt.where(JobRun.job_id == job_id)
    if profile_id is not None:
        stmt = stmt.where(Job.profile_id == profile_id)
    if user is not None:
        stmt = apply_owner_scope(stmt, Job.owner_sub, user)

    result = await db.execute(stmt)
    runs = list(result.scalars().all())
    if not runs:
        return []

    checks_by_run = await _fetch_checks_by_run(db, [run.id for run in runs])
    return build_timeline_points(runs, checks_by_run)


async def fetch_compliance_by_host(db: AsyncSession, run_id: int) -> list[HostCompliancePoint]:
    result = await db.execute(select(CheckResult).where(CheckResult.job_run_id == run_id))
    checks = list(result.scalars().all())
    if not checks:
        return []

    host_ids = {check.host_id for check in checks}
    hosts_result = await db.execute(select(Host).where(Host.id.in_(host_ids)))
    host_names = {host.id: host.name for host in hosts_result.scalars().all()}
    return aggregate_checks_by_host(checks, host_names)


async def fetch_compliance_by_profile(
    db: AsyncSession,
    days: int = 30,
    user=None,
    date_from: date | None = None,
    date_to: date | None = None,
) -> list[ProfileCompliancePoint]:
    start, end, _span = resolve_period(days=days, date_from=date_from, date_to=date_to)
    latest_per_job = (
        select(
            JobRun.job_id.label("job_id"),
            func.max(JobRun.finished_at).label("max_finished"),
        )
        .where(
            JobRun.status == JobStatus.COMPLETED,
            JobRun.finished_at.isnot(None),
            JobRun.finished_at >= start,
            JobRun.finished_at <= end,
        )
        .group_by(JobRun.job_id)
        .subquery()
    )

    stmt = (
        select(JobRun)
        .join(
            latest_per_job,
            and_(
                JobRun.job_id == latest_per_job.c.job_id,
                JobRun.finished_at == latest_per_job.c.max_finished,
            ),
        )
        .join(Job, JobRun.job_id == Job.id)
        .where(Job.is_active.is_(True), Job.profile_id.isnot(None))
        .options(selectinload(JobRun.job).selectinload(Job.profile))
    )
    if user is not None:
        stmt = apply_owner_scope(stmt, Job.owner_sub, user)
    result = await db.execute(stmt)
    runs = list(result.scalars().unique().all())
    if not runs:
        return []

    profile_ids = {run.job.profile_id for run in runs if run.job and run.job.profile_id is not None}
    profiles_result = await db.execute(select(Profile).where(Profile.id.in_(profile_ids)))
    profiles = {profile.id: profile for profile in profiles_result.scalars().all()}

    checks_by_run = await _fetch_checks_by_run(db, [run.id for run in runs])
    return aggregate_profile_compliance(runs, checks_by_run, profiles)


def _status_value(status) -> str:
    return status.value if hasattr(status, "value") else str(status)


def _avg(values: list[float]) -> float | None:
    if not values:
        return None
    return round(sum(values) / len(values), 2)


def _platform_of(os_type: str | None) -> str:
    value = (os_type or "").strip().lower()
    if value in {"windows", "win"}:
        return "windows"
    if value in {"network", "network device"}:
        return "network"
    if value:
        return "linux"
    return "unknown"


def build_ops_overview(
    *,
    days: int,
    completed_runs: list,
    period_runs: list,
    checks: list,
    host_os: dict[int, str],
    waiver_approved: int,
    waiver_pending: int,
    prev_avg: float | None,
) -> ComplianceOpsOverview:
    checks_by_run: dict[int, list] = defaultdict(list)
    outcome: dict[str, int] = defaultdict(int)
    fail_rules: dict[str, int] = defaultdict(int)
    host_ids: set[int] = set()
    profile_ids: set[int] = set()

    for check in checks:
        checks_by_run[check.job_run_id].append(check)
        status = _status_value(check.status)
        outcome[status] += 1
        host_ids.add(check.host_id)
        if status == CheckStatus.FAIL.value:
            fail_rules[check.rule_tech_name] += 1

    run_percents: list[float] = []
    bands = {"high": 0, "mid": 0, "low": 0}
    daily: dict[str, dict] = {}
    heat: dict[tuple[int, int], list[float]] = defaultdict(list)
    job_acc: dict[int, dict] = {}
    first_monday = None
    dated_runs: list[tuple[object, object, object]] = []

    for run in completed_runs:
        summary = build_report_summary(run.id, checks_by_run.get(run.id, []))
        run_percents.append(summary.compliance_percent)
        if summary.compliance_percent >= 80:
            bands["high"] += 1
        elif summary.compliance_percent >= 50:
            bands["mid"] += 1
        else:
            bands["low"] += 1
        job = getattr(run, "job", None)
        if job is not None and getattr(job, "profile_id", None):
            profile_ids.add(job.profile_id)
        job_id = getattr(run, "job_id", None)
        if job_id is not None:
            bucket = job_acc.setdefault(
                job_id,
                {
                    "name": getattr(job, "name", None) or f"Job #{job_id}",
                    "runs": 0,
                    "pcts": [],
                    "passed": 0,
                    "failed": 0,
                    "latest_run_id": None,
                    "latest_finished": None,
                },
            )
            bucket["runs"] += 1
            bucket["pcts"].append(summary.compliance_percent)
            bucket["passed"] += summary.passed
            bucket["failed"] += summary.failed
            finished_at = getattr(run, "finished_at", None)
            latest_finished = bucket["latest_finished"]
            if latest_finished is None or (finished_at is not None and finished_at >= latest_finished):
                bucket["latest_run_id"] = run.id
                bucket["latest_finished"] = finished_at
        finished = run.finished_at
        if finished is None:
            continue
        if finished.tzinfo is None:
            finished = finished.replace(tzinfo=UTC)
        day = finished.date().isoformat()
        bucket = daily.setdefault(day, {"runs": 0, "passed": 0, "failed": 0, "pcts": []})
        bucket["runs"] += 1
        bucket["passed"] += summary.passed
        bucket["failed"] += summary.failed
        bucket["pcts"].append(summary.compliance_percent)
        monday = finished.date() - timedelta(days=finished.weekday())
        if first_monday is None or monday < first_monday:
            first_monday = monday
        dated_runs.append((finished, monday, summary))

    for finished, monday, summary in dated_runs:
        week_index = 0 if first_monday is None else (monday - first_monday).days // 7
        heat[(week_index, finished.weekday())].append(summary.compliance_percent)

    week_count = max((key[0] for key in heat), default=-1) + 1
    heatmap = [
        WeekdayHeatCell(
            weekday=weekday,
            week_index=week,
            week_start=(first_monday + timedelta(weeks=week)).isoformat() if first_monday else None,
            day=(first_monday + timedelta(weeks=week, days=weekday)).isoformat() if first_monday else None,
            avg_compliance_percent=_avg(heat.get((week, weekday), [])),
            runs=len(heat.get((week, weekday), [])),
        )
        for week in range(week_count)
        for weekday in range(7)
    ]

    platform_acc: dict[str, dict] = defaultdict(lambda: {"hosts": set(), "pass": 0, "fail": 0, "total": 0})
    for check in checks:
        platform = _platform_of(host_os.get(check.host_id))
        bucket = platform_acc[platform]
        bucket["hosts"].add(check.host_id)
        bucket["total"] += 1
        status = _status_value(check.status)
        if status == CheckStatus.PASS.value:
            bucket["pass"] += 1
        elif status == CheckStatus.FAIL.value:
            bucket["fail"] += 1

    run_status: dict[str, int] = defaultdict(int)
    for run in period_runs:
        run_status[_status_value(run.status)] += 1

    kpis = ComplianceOpsKpis(
        avg_compliance_percent=_avg(run_percents),
        prev_avg_compliance_percent=prev_avg,
        completed_runs=len(completed_runs),
        failed_runs=run_status.get(JobStatus.FAILED.value, 0),
        running_runs=run_status.get(JobStatus.RUNNING.value, 0),
        total_checks=sum(outcome.values()),
        passed=outcome.get(CheckStatus.PASS.value, 0),
        failed=outcome.get(CheckStatus.FAIL.value, 0),
        skipped=outcome.get(CheckStatus.SKIP.value, 0),
        errors=outcome.get(CheckStatus.ERROR.value, 0),
        hosts=len(host_ids),
        profiles=len(profile_ids),
        jobs=len(job_acc),
        waivers_approved=waiver_approved,
        waivers_pending=waiver_pending,
    )

    return ComplianceOpsOverview(
        days=days,
        kpis=kpis,
        outcome_mix=[StatusCountPoint(key=key, count=count) for key, count in sorted(outcome.items())],
        run_status_mix=[StatusCountPoint(key=key, count=count) for key, count in sorted(run_status.items())],
        bands=[
            ComplianceBandPoint(band="high", count=bands["high"]),
            ComplianceBandPoint(band="mid", count=bands["mid"]),
            ComplianceBandPoint(band="low", count=bands["low"]),
        ],
        daily=[
            DailyOpsPoint(
                day=day,
                runs=item["runs"],
                passed=item["passed"],
                failed=item["failed"],
                avg_compliance_percent=_avg(item["pcts"]) or 0,
            )
            for day, item in sorted(daily.items())
        ],
        by_platform=[
            PlatformOpsPoint(
                platform=platform,
                hosts=len(item["hosts"]),
                checks=item["total"],
                avg_compliance_percent=round((item["pass"] / item["total"]) * 100, 2) if item["total"] else 0,
            )
            for platform, item in sorted(platform_acc.items())
        ],
        by_job=[
            JobOpsPoint(
                job_id=job_id,
                job_name=item["name"],
                runs=item["runs"],
                avg_compliance_percent=_avg(item["pcts"]) or 0,
                passed=item["passed"],
                failed=item["failed"],
                latest_run_id=item["latest_run_id"],
            )
            for job_id, item in sorted(
                job_acc.items(),
                key=lambda pair: (-pair[1]["runs"], pair[1]["name"]),
            )
        ],
        top_failing_rules=[
            RuleFailPoint(rule_tech_name=rule, fail_count=count)
            for rule, count in sorted(fail_rules.items(), key=lambda item: (-item[1], item[0]))[:10]
        ],
        heatmap=heatmap,
    )


async def fetch_compliance_ops_overview(
    db: AsyncSession,
    days: int = 30,
    user=None,
    date_from: date | None = None,
    date_to: date | None = None,
) -> ComplianceOpsOverview:
    start, end, span_days = resolve_period(days=days, date_from=date_from, date_to=date_to)
    prev_start = start - (end - start)

    completed_stmt = (
        select(JobRun)
        .join(Job, JobRun.job_id == Job.id)
        .options(selectinload(JobRun.job))
        .where(
            JobRun.status == JobStatus.COMPLETED,
            JobRun.finished_at.isnot(None),
            JobRun.finished_at >= start,
            JobRun.finished_at <= end,
        )
        .order_by(JobRun.finished_at.asc())
        .limit(2000)
    )
    if user is not None:
        completed_stmt = apply_owner_scope(completed_stmt, Job.owner_sub, user)
    completed_runs = list((await db.execute(completed_stmt)).scalars().unique().all())

    period_stmt = (
        select(JobRun)
        .join(Job, JobRun.job_id == Job.id)
        .where(JobRun.created_at >= start, JobRun.created_at <= end)
        .limit(2000)
    )
    if user is not None:
        period_stmt = apply_owner_scope(period_stmt, Job.owner_sub, user)
    period_runs = list((await db.execute(period_stmt)).scalars().unique().all())

    prev_stmt = (
        select(JobRun)
        .join(Job, JobRun.job_id == Job.id)
        .options(selectinload(JobRun.job))
        .where(
            JobRun.status == JobStatus.COMPLETED,
            JobRun.finished_at.isnot(None),
            JobRun.finished_at >= prev_start,
            JobRun.finished_at < start,
        )
        .limit(2000)
    )
    if user is not None:
        prev_stmt = apply_owner_scope(prev_stmt, Job.owner_sub, user)
    prev_runs = list((await db.execute(prev_stmt)).scalars().unique().all())

    run_ids = [run.id for run in completed_runs]
    checks_by_run = await _fetch_checks_by_run(db, run_ids)
    checks = [check for group in checks_by_run.values() for check in group]

    prev_avg = None
    if prev_runs:
        prev_checks = await _fetch_checks_by_run(db, [run.id for run in prev_runs])
        prev_avg = _avg(
            [
                build_report_summary(run.id, prev_checks.get(run.id, [])).compliance_percent
                for run in prev_runs
            ]
        )

    host_ids = {check.host_id for check in checks}
    host_os: dict[int, str] = {}
    if host_ids:
        hosts = (await db.execute(select(Host).where(Host.id.in_(host_ids)))).scalars().all()
        host_os = {host.id: host.os_type or "" for host in hosts}

    waiver_stmt = select(ComplianceWaiver.status, func.count()).where(ComplianceWaiver.is_active.is_(True))
    if user is not None:
        waiver_stmt = apply_owner_scope(waiver_stmt, ComplianceWaiver.owner_sub, user)
    waiver_stmt = waiver_stmt.group_by(ComplianceWaiver.status)
    waiver_rows = (await db.execute(waiver_stmt)).all()
    waiver_counts = {_status_value(status): count for status, count in waiver_rows}

    return build_ops_overview(
        days=span_days,
        completed_runs=completed_runs,
        period_runs=period_runs,
        checks=checks,
        host_os=host_os,
        waiver_approved=waiver_counts.get(WaiverStatus.APPROVED.value, 0),
        waiver_pending=waiver_counts.get(WaiverStatus.PENDING.value, 0),
        prev_avg=prev_avg,
    )
