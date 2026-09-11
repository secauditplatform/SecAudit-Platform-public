"""API service helpers for compliance waivers."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import AuthUser
from app.models import ComplianceWaiver, Job, Profile, UserRole, WaiverStatus
from app.services.object_rbac import apply_owner_scope, assert_can_access
from secaudit_core.object_rbac import ownership_sub_for_create


def new_owner_sub(user: AuthUser) -> str:
    return ownership_sub_for_create(user.sub)


async def get_waiver_or_404(db: AsyncSession, waiver_id: int) -> ComplianceWaiver:
    waiver = await db.get(ComplianceWaiver, waiver_id)
    if not waiver:
        raise HTTPException(status_code=404, detail="Waiver not found")
    return waiver


async def assert_profile_exists(db: AsyncSession, profile_id: int) -> Profile:
    profile = await db.get(Profile, profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return profile


async def assert_job_scope(db: AsyncSession, user: AuthUser, job_id: int | None) -> Job | None:
    if job_id is None:
        return None
    job = await db.get(Job, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    assert_can_access(user, job.owner_sub, detail="Job not found")
    return job


def actor_name(user: AuthUser) -> str:
    return user.username or user.sub or "unknown"


def transition_approve(waiver: ComplianceWaiver, user: AuthUser) -> None:
    if waiver.status != WaiverStatus.PENDING or not waiver.is_active:
        raise HTTPException(status_code=400, detail="Only pending waivers can be approved")
    if waiver.requested_by == actor_name(user) and not user.has_role(UserRole.ADMIN):
        raise HTTPException(status_code=400, detail="Requester cannot approve their own waiver")
    now = datetime.now(UTC)
    waiver.status = WaiverStatus.APPROVED
    waiver.approved_by = actor_name(user)
    waiver.approved_at = now
    waiver.rejected_by = None
    waiver.rejected_at = None
    waiver.rejection_reason = None
    waiver.is_active = True


def transition_reject(waiver: ComplianceWaiver, user: AuthUser, reason: str | None) -> None:
    if waiver.status != WaiverStatus.PENDING or not waiver.is_active:
        raise HTTPException(status_code=400, detail="Only pending waivers can be rejected")
    now = datetime.now(UTC)
    waiver.status = WaiverStatus.REJECTED
    waiver.rejected_by = actor_name(user)
    waiver.rejected_at = now
    waiver.rejection_reason = reason
    waiver.is_active = False


def transition_revoke(waiver: ComplianceWaiver, _user: AuthUser) -> None:
    if waiver.status != WaiverStatus.APPROVED or not waiver.is_active:
        raise HTTPException(status_code=400, detail="Only approved active waivers can be revoked")
    waiver.status = WaiverStatus.REVOKED
    waiver.is_active = False


async def list_waivers(
    db: AsyncSession,
    user: AuthUser,
    *,
    profile_id: int | None = None,
    host_id: int | None = None,
    job_id: int | None = None,
    status: WaiverStatus | None = None,
    active_only: bool | None = None,
) -> list[ComplianceWaiver]:
    stmt = select(ComplianceWaiver).order_by(ComplianceWaiver.id.desc())
    stmt = apply_owner_scope(stmt, ComplianceWaiver.owner_sub, user)
    if profile_id is not None:
        stmt = stmt.where(ComplianceWaiver.profile_id == profile_id)
    if host_id is not None:
        stmt = stmt.where(ComplianceWaiver.host_id == host_id)
    if job_id is not None:
        stmt = stmt.where(ComplianceWaiver.job_id == job_id)
    if status is not None:
        stmt = stmt.where(ComplianceWaiver.status == status)
    if active_only is True:
        stmt = stmt.where(ComplianceWaiver.is_active.is_(True))
    elif active_only is False:
        stmt = stmt.where(ComplianceWaiver.is_active.is_(False))
    result = await db.execute(stmt)
    return list(result.scalars().all())
