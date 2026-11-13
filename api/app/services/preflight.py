"""API-side preflight dispatch and profile applicability preview."""

from __future__ import annotations

from pathlib import Path

from celery.exceptions import TimeoutError as CeleryTimeoutError
from celery.result import AsyncResult
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.blocking import run_blocking
from app.core.config import settings
from app.models import Host, Profile, ProfileVersion
from secaudit_core.celery_dispatch import send_task
from secaudit_core.celery_redis import create_celery_app
from secaudit_core.preflight import platforms_compatible, profile_platform
from secaudit_core.profile_packages import count_profile_rules_metadata


def _wait_preflight_result(task_id: str, *, timeout: float = 25.0) -> dict:
    app = create_celery_app("secaudit-preflight-wait", settings)
    async_result = AsyncResult(task_id, app=app)
    return async_result.get(timeout=timeout)


async def dispatch_host_probe(host_id: int, credential_id: int | None = None) -> dict:
    task_id = send_task(
        "app.tasks.preflight.probe_host",
        args=[host_id, credential_id],
        broker_url=settings.celery_broker_url,
        queue="inventory",
    )
    try:
        return await run_blocking(_wait_preflight_result, task_id, timeout=25.0)
    except CeleryTimeoutError as exc:
        raise HTTPException(status_code=504, detail="Preflight probe timed out") from exc
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Preflight probe failed: {exc}") from exc


async def profile_applicability(
    db: AsyncSession,
    *,
    profile_id: int,
    host_ids: list[int],
    profile_version_id: int | None = None,
) -> dict:
    result = await db.execute(
        select(Profile).options(selectinload(Profile.category)).where(Profile.id == profile_id)
    )
    profile = result.scalar_one_or_none()
    if profile is None:
        raise HTTPException(status_code=404, detail="Profile not found")

    rules_count = 0
    if profile_version_id is not None:
        version = await db.get(ProfileVersion, profile_version_id)
        if version is None or version.profile_id != profile.id:
            raise HTTPException(status_code=404, detail="Profile version not found")
        rules_count = len(version.requirement_ids or [])
    elif profile.package_path:
        package_dir = Path(profile.package_path)
        if package_dir.is_dir():
            rules_count = count_profile_rules_metadata(package_dir)
    if not rules_count and profile.package_path is None:
        # Custom profiles without a package: fall back to active version if any.
        active = await db.execute(
            select(ProfileVersion).where(
                ProfileVersion.profile_id == profile.id,
                ProfileVersion.is_active.is_(True),
            )
        )
        active_version = active.scalar_one_or_none()
        if active_version is not None:
            rules_count = len(active_version.requirement_ids or [])

    plat = profile_platform(
        os_name=profile.os_name,
        category_name=profile.category.name if profile.category else None,
        category_slug=getattr(profile.category, "slug", None) if profile.category else None,
    )

    hosts: list[Host] = []
    if host_ids:
        rows = await db.execute(select(Host).where(Host.id.in_(host_ids), Host.is_ephemeral.is_(False)))
        hosts = list(rows.scalars().all())

    host_rows = []
    applicable = 0
    for host in hosts:
        ok = platforms_compatible(host.os_type, plat)
        if ok:
            applicable += 1
        host_rows.append(
            {
                "host_id": host.id,
                "host_name": host.name or host.hostname,
                "os_type": host.os_type,
                "applicable": ok,
                "reason": None if ok else "os_mismatch",
            }
        )

    total = len(host_rows)
    return {
        "profile_id": profile.id,
        "profile_name": profile.profile_name,
        "profile_platform": plat,
        "rules_count": rules_count,
        "hosts_total": total,
        "hosts_applicable": applicable,
        "hosts_inapplicable": total - applicable,
        "hosts": host_rows,
    }
