"""Validate network vs standard job scope against profiles and hosts."""

from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import Host, JobScope, Profile
from secaudit_core.enums import NetworkCheckMode
from secaudit_core.network_scope import (
    assert_network_hosts,
    assert_scope_matches_profile,
    assert_standard_hosts,
    default_network_check_mode,
    profile_is_network,
)


async def load_profile(db: AsyncSession, profile_id: int | None) -> Profile | None:
    if profile_id is None:
        return None
    result = await db.execute(
        select(Profile).options(selectinload(Profile.category)).where(Profile.id == profile_id)
    )
    return result.scalar_one_or_none()


async def load_hosts(db: AsyncSession, host_ids: list[int]) -> list[Host]:
    if not host_ids:
        return []
    result = await db.execute(select(Host).where(Host.id.in_(host_ids)))
    return list(result.scalars().all())


async def validate_job_scope(
    db: AsyncSession,
    *,
    scope: JobScope,
    profile_id: int | None,
    host_ids: list[int],
    network_check_mode: NetworkCheckMode | None = None,
) -> NetworkCheckMode | None:
    profile = await load_profile(db, profile_id)
    try:
        assert_scope_matches_profile(scope, profile)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    hosts = await load_hosts(db, host_ids)
    try:
        if scope == JobScope.NETWORK:
            assert_network_hosts(hosts)
        elif hosts:
            assert_standard_hosts(hosts)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if scope == JobScope.NETWORK:
        return network_check_mode or default_network_check_mode()
    if network_check_mode is not None:
        raise HTTPException(status_code=400, detail="network_check_mode applies only to network jobs")
    return None


def profile_allowed_for_scope(profile: Profile, scope: JobScope) -> bool:
    is_network = profile_is_network(profile)
    return is_network if scope == JobScope.NETWORK else not is_network
