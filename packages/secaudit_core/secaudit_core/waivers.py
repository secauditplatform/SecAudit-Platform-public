"""Compliance waiver matching, scoring helpers, and expiry sweeper."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Iterable

from sqlalchemy import Select, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from secaudit_core.enums import CheckStatus, WaiverStatus
from secaudit_core.models import ComplianceWaiver


def waiver_is_effective(
    waiver: ComplianceWaiver,
    *,
    now: datetime | None = None,
) -> bool:
    if not waiver.is_active or waiver.status != WaiverStatus.APPROVED:
        return False
    if waiver.expires_at is None:
        return True
    current = now or datetime.now(UTC)
    expires = waiver.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=UTC)
    return expires > current


def host_scope_view(host: object) -> tuple[str | None, str | None, set[str]]:
    tags: set[str] = set()
    for link in getattr(host, "tags", ()) or ():
        tag = getattr(link, "tag", None)
        name = getattr(tag, "name", None) if tag is not None else None
        if name:
            tags.add(str(name))
    site = getattr(host, "site", None)
    environment = getattr(host, "environment", None)
    return (str(site) if site else None, str(environment) if environment else None, tags)


def waiver_matches_check(
    waiver: ComplianceWaiver,
    *,
    profile_id: int,
    rule_tech_name: str,
    host_id: int,
    job_id: int | None,
    host_site: str | None = None,
    host_environment: str | None = None,
    host_tags: set[str] | None = None,
) -> bool:
    if waiver.profile_id != profile_id:
        return False
    if waiver.rule_tech_name != rule_tech_name:
        return False
    if waiver.host_id is not None and waiver.host_id != host_id:
        return False
    if waiver.job_id is not None and waiver.job_id != job_id:
        return False
    needs_host = bool(waiver.scope_site or waiver.scope_environment or waiver.scope_tag)
    if needs_host and host_site is None and host_environment is None and not host_tags:
        if waiver.scope_site or waiver.scope_environment or waiver.scope_tag:
            return False
    if waiver.scope_site and waiver.scope_site != (host_site or ""):
        return False
    if waiver.scope_environment and waiver.scope_environment != (host_environment or ""):
        return False
    if waiver.scope_tag and waiver.scope_tag not in (host_tags or set()):
        return False
    return True


def find_matching_waiver(
    waivers: Iterable[ComplianceWaiver],
    *,
    profile_id: int,
    rule_tech_name: str,
    host_id: int,
    job_id: int | None,
    now: datetime | None = None,
    hosts: dict | None = None,
) -> ComplianceWaiver | None:
    """Prefer more specific scope: host+job, then tag, site, and environment."""
    host = (hosts or {}).get(host_id)
    host_site, host_environment, host_tags = host_scope_view(host) if host is not None else (None, None, set())

    def specificity(waiver: ComplianceWaiver) -> tuple[int, int, int, int, int, int]:
        return (
            1 if waiver.host_id is not None else 0,
            1 if waiver.job_id is not None else 0,
            1 if waiver.scope_tag else 0,
            1 if waiver.scope_site else 0,
            1 if waiver.scope_environment else 0,
            waiver.id,
        )

    matches = [
        w
        for w in waivers
        if waiver_is_effective(w, now=now)
        and waiver_matches_check(
            w,
            profile_id=profile_id,
            rule_tech_name=rule_tech_name,
            host_id=host_id,
            job_id=job_id,
            host_site=host_site,
            host_environment=host_environment,
            host_tags=host_tags,
        )
    ]
    if not matches:
        return None
    return sorted(matches, key=specificity, reverse=True)[0]


def active_waivers_select(
    *,
    profile_id: int | None = None,
    host_id: int | None = None,
    job_id: int | None = None,
) -> Select[tuple[ComplianceWaiver]]:
    stmt = select(ComplianceWaiver).where(
        ComplianceWaiver.is_active.is_(True),
        ComplianceWaiver.status == WaiverStatus.APPROVED,
        or_(ComplianceWaiver.expires_at.is_(None), ComplianceWaiver.expires_at > datetime.now(UTC)),
    )
    if profile_id is not None:
        stmt = stmt.where(ComplianceWaiver.profile_id == profile_id)
    if host_id is not None:
        stmt = stmt.where(or_(ComplianceWaiver.host_id.is_(None), ComplianceWaiver.host_id == host_id))
    if job_id is not None:
        stmt = stmt.where(or_(ComplianceWaiver.job_id.is_(None), ComplianceWaiver.job_id == job_id))
    return stmt.order_by(ComplianceWaiver.id.desc())


async def load_active_waivers(
    db: AsyncSession,
    *,
    profile_id: int | None = None,
    host_id: int | None = None,
    job_id: int | None = None,
) -> list[ComplianceWaiver]:
    result = await db.execute(
        active_waivers_select(profile_id=profile_id, host_id=host_id, job_id=job_id)
    )
    return list(result.scalars().all())


def load_active_waivers_sync(
    db: Session,
    *,
    profile_id: int | None = None,
    host_id: int | None = None,
    job_id: int | None = None,
) -> list[ComplianceWaiver]:
    result = db.execute(active_waivers_select(profile_id=profile_id, host_id=host_id, job_id=job_id))
    return list(result.scalars().all())


async def load_active_waivers_for_profiles(
    db: AsyncSession,
    profile_ids: Iterable[int],
) -> list[ComplianceWaiver]:
    ids = {int(profile_id) for profile_id in profile_ids if profile_id is not None}
    if not ids:
        return []
    stmt = active_waivers_select().where(ComplianceWaiver.profile_id.in_(ids))
    result = await db.execute(stmt)
    return list(result.scalars().all())


def waived_fail_ids(
    checks: Iterable,
    waivers: Iterable[ComplianceWaiver],
    *,
    profile_id: int | None,
    job_id: int | None,
    now: datetime | None = None,
    hosts: dict | None = None,
) -> dict[int, ComplianceWaiver]:
    if profile_id is None:
        return {}
    mapped: dict[int, ComplianceWaiver] = {}
    for check in checks:
        status = check.status.value if hasattr(check.status, "value") else str(check.status)
        if status != CheckStatus.FAIL.value:
            continue
        match = find_matching_waiver(
            waivers,
            profile_id=profile_id,
            rule_tech_name=check.rule_tech_name,
            host_id=check.host_id,
            job_id=job_id,
            now=now,
            hosts=hosts,
        )
        if match is not None:
            mapped[check.id] = match
    return mapped


def resolve_waived_fail_map(
    checks: Iterable,
    waivers: Iterable[ComplianceWaiver],
    *,
    profile_id: int | None,
    job_id: int | None,
    now: datetime | None = None,
    hosts: dict | None = None,
) -> dict[int, ComplianceWaiver]:
    """Map FAIL check ids covered by an active waiver for one run context."""
    return waived_fail_ids(
        checks,
        waivers,
        profile_id=profile_id,
        job_id=job_id,
        now=now,
        hosts=hosts,
    )


async def resolve_waived_fail_map_async(
    db: AsyncSession,
    checks: Iterable,
    *,
    profile_id: int | None,
    job_id: int | None,
) -> dict[int, ComplianceWaiver]:
    if profile_id is None:
        return {}
    waivers = await load_active_waivers(db, profile_id=profile_id, job_id=job_id)
    hosts = await load_waiver_hosts(db, checks)
    return resolve_waived_fail_map(
        checks, waivers, profile_id=profile_id, job_id=job_id, hosts=hosts
    )


def resolve_waived_fail_map_sync(
    db: Session,
    checks: Iterable,
    *,
    profile_id: int | None,
    job_id: int | None,
) -> dict[int, ComplianceWaiver]:
    if profile_id is None:
        return {}
    waivers = load_active_waivers_sync(db, profile_id=profile_id, job_id=job_id)
    hosts = load_waiver_hosts_sync(db, checks)
    return resolve_waived_fail_map(
        checks, waivers, profile_id=profile_id, job_id=job_id, hosts=hosts
    )


def _waiver_host_ids(checks: Iterable) -> set[int]:
    ids: set[int] = set()
    for check in checks:
        host_id = getattr(check, "host_id", None)
        if host_id is not None:
            ids.add(int(host_id))
    return ids


def _hosts_stmt(host_ids: set[int]):
    from sqlalchemy.orm import selectinload

    from secaudit_core.models import Host, HostTagLink

    return (
        select(Host)
        .options(selectinload(Host.tags).selectinload(HostTagLink.tag))
        .where(Host.id.in_(host_ids))
    )


async def load_waiver_hosts(db: AsyncSession, checks: Iterable) -> dict:
    host_ids = _waiver_host_ids(checks)
    if not host_ids:
        return {}
    result = await db.execute(_hosts_stmt(host_ids))
    return {host.id: host for host in result.scalars().all()}


def load_waiver_hosts_sync(db: Session, checks: Iterable) -> dict:
    host_ids = _waiver_host_ids(checks)
    if not host_ids:
        return {}
    result = db.execute(_hosts_stmt(host_ids))
    return {host.id: host for host in result.scalars().all()}


def waived_ids_by_run(
    runs: Iterable,
    checks_by_run: dict[int, list],
    waivers: Iterable[ComplianceWaiver],
    hosts: dict | None = None,
) -> dict[int, set[int]]:
    """Batch-resolve waived FAIL check ids for runs that already have ``job`` loaded."""
    by_profile: dict[int, list[ComplianceWaiver]] = {}
    for waiver in waivers:
        by_profile.setdefault(waiver.profile_id, []).append(waiver)

    out: dict[int, set[int]] = {}
    for run in runs:
        job = getattr(run, "job", None)
        profile_id = job.profile_id if job is not None else None
        if profile_id is None:
            out[run.id] = set()
            continue
        mapped = resolve_waived_fail_map(
            checks_by_run.get(run.id, []),
            by_profile.get(profile_id, []),
            profile_id=profile_id,
            job_id=run.job_id,
            hosts=hosts,
        )
        out[run.id] = set(mapped.keys())
    return out


def expire_due_waivers(db: Session, *, now: datetime | None = None) -> list[int]:
    current = now or datetime.now(UTC)
    rows = list(
        db.execute(
            select(ComplianceWaiver).where(
                ComplianceWaiver.is_active.is_(True),
                ComplianceWaiver.status == WaiverStatus.APPROVED,
                ComplianceWaiver.expires_at.is_not(None),
                ComplianceWaiver.expires_at <= current,
            )
        ).scalars().all()
    )
    expired_ids: list[int] = []
    for waiver in rows:
        waiver.status = WaiverStatus.EXPIRED
        waiver.is_active = False
        expired_ids.append(waiver.id)
    return expired_ids


def find_expiring_waivers(
    db: Session,
    *,
    within_days: int = 7,
    now: datetime | None = None,
) -> list[ComplianceWaiver]:
    """Approved active waivers whose expires_at falls within the next ``within_days``."""
    current = now or datetime.now(UTC)
    horizon = current + timedelta(days=max(1, int(within_days)))
    return list(
        db.execute(
            select(ComplianceWaiver).where(
                ComplianceWaiver.is_active.is_(True),
                ComplianceWaiver.status == WaiverStatus.APPROVED,
                ComplianceWaiver.expires_at.is_not(None),
                ComplianceWaiver.expires_at > current,
                ComplianceWaiver.expires_at <= horizon,
            )
        )
        .scalars()
        .all()
    )
