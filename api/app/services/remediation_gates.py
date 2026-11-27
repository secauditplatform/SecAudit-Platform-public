"""API-side maintenance window and change_ticket gates for remediation starts."""

from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models import Host, HostTag, HostTagLink, MaintenanceWindow, RemediationJob, RemediationJobHost
from secaudit_core.maintenance_windows import remediation_blocked_by_windows
from secaudit_core.remediation_backup import ticket_envs


async def load_job_hosts(db: AsyncSession, job: RemediationJob) -> list[Host]:
    explicit = list(
        (
            await db.execute(
                select(RemediationJobHost.host_id).where(
                    RemediationJobHost.remediation_job_id == job.id
                )
            )
        ).scalars().all()
    )
    if explicit:
        rows = await db.execute(select(Host).where(Host.id.in_(explicit), Host.is_active.is_(True)))
        return list(rows.scalars().all())

    dynamic_filter = job.dynamic_filter or {}
    if not dynamic_filter:
        return []
    stmt = select(Host).where(Host.is_ephemeral.is_(False))
    if job.enforce_host_owner_scope:
        if not job.owner_sub:
            return []
        stmt = stmt.where(Host.owner_sub == job.owner_sub)
    if dynamic_filter.get("active_only", True):
        stmt = stmt.where(Host.is_active.is_(True))
    site = (dynamic_filter.get("site") or "").strip()
    if site:
        stmt = stmt.where(Host.site == site)
    environment = (dynamic_filter.get("environment") or "").strip()
    if environment:
        stmt = stmt.where(Host.environment == environment)
    os_type = (dynamic_filter.get("os_type") or "").strip()
    if os_type:
        stmt = stmt.where(Host.os_type == os_type)
    tags = [t.strip() for t in dynamic_filter.get("tags", []) if str(t).strip()]
    if tags:
        stmt = (
            stmt.join(HostTagLink, HostTagLink.host_id == Host.id)
            .join(HostTag, HostTag.id == HostTagLink.tag_id)
            .where(HostTag.name.in_(tags))
            .distinct()
        )
    rows = await db.execute(stmt)
    return list(rows.scalars().unique().all())


async def assert_remediation_allowed(
    db: AsyncSession,
    job: RemediationJob,
    *,
    change_ticket: str | None,
) -> None:
    hosts = await load_job_hosts(db, job)
    if not hosts:
        raise HTTPException(status_code=400, detail="No active hosts assigned to remediation job")

    windows = list(
        (await db.execute(select(MaintenanceWindow).where(MaintenanceWindow.enabled.is_(True)))).scalars().all()
    )
    blocked = remediation_blocked_by_windows(windows, hosts)
    if blocked:
        raise HTTPException(status_code=409, detail=blocked)

    need = ticket_envs(settings)
    if need and any((host.environment or "").strip().lower() in need for host in hosts):
        if not (change_ticket or "").strip():
            raise HTTPException(
                status_code=422,
                detail="change_ticket is required for production remediation",
            )
