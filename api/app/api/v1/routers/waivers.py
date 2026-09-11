from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import AuthUser, require_roles
from app.core.database import get_db
from app.models import ComplianceWaiver, Host, UserRole, WaiverStatus
from app.schemas import (
    ComplianceWaiverCreate,
    ComplianceWaiverRead,
    ComplianceWaiverReject,
    ComplianceWaiverUpdate,
)
from app.services.audit_log import log_audit_event
from app.services.object_rbac import assert_can_access
from app.services.waivers import (
    actor_name,
    assert_job_scope,
    assert_profile_exists,
    get_waiver_or_404,
    list_waivers,
    new_owner_sub,
    transition_approve,
    transition_reject,
    transition_revoke,
)

router = APIRouter()

_READ_ROLES = (UserRole.ADMIN, UserRole.OPERATOR)
_WRITE_ROLES = (UserRole.ADMIN, UserRole.OPERATOR)
_APPROVE_ROLES = (UserRole.ADMIN, UserRole.OPERATOR)


def _to_read(waiver: ComplianceWaiver) -> ComplianceWaiverRead:
    return ComplianceWaiverRead.model_validate(waiver)


@router.get("", response_model=list[ComplianceWaiverRead])
async def list_compliance_waivers(
    profile_id: int | None = None,
    host_id: int | None = None,
    job_id: int | None = None,
    status: WaiverStatus | None = None,
    active_only: bool | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(*_READ_ROLES)),
) -> list[ComplianceWaiverRead]:
    rows = await list_waivers(
        db,
        user,
        profile_id=profile_id,
        host_id=host_id,
        job_id=job_id,
        status=status,
        active_only=active_only,
    )
    return [_to_read(row) for row in rows]


@router.post("", response_model=ComplianceWaiverRead, status_code=201)
async def create_compliance_waiver(
    data: ComplianceWaiverCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(*_WRITE_ROLES)),
) -> ComplianceWaiverRead:
    await assert_profile_exists(db, data.profile_id)
    await assert_job_scope(db, user, data.job_id)
    if data.host_id is not None:
        host = await db.get(Host, data.host_id)
        if not host:
            raise HTTPException(status_code=404, detail="Host not found")
        assert_can_access(user, host.owner_sub, detail="Host not found")

    auto_approve = bool(data.auto_approve and user.has_role(UserRole.ADMIN))
    now = datetime.now(UTC)
    waiver = ComplianceWaiver(
        profile_id=data.profile_id,
        rule_tech_name=data.rule_tech_name.strip(),
        host_id=data.host_id,
        job_id=data.job_id,
        reason=data.reason.strip(),
        status=WaiverStatus.APPROVED if auto_approve else WaiverStatus.PENDING,
        requested_by=actor_name(user),
        approved_by=actor_name(user) if auto_approve else None,
        approved_at=now if auto_approve else None,
        expires_at=data.expires_at,
        is_active=True,
        owner_sub=new_owner_sub(user),
    )
    if not waiver.rule_tech_name or not waiver.reason:
        raise HTTPException(status_code=400, detail="rule_tech_name and reason are required")

    db.add(waiver)
    await db.flush()
    await db.refresh(waiver)
    await log_audit_event(
        db,
        request,
        user,
        action="waiver.create",
        resource_type="compliance_waiver",
        resource_id=waiver.id,
        resource_name=waiver.rule_tech_name,
        metadata={
            "profile_id": waiver.profile_id,
            "host_id": waiver.host_id,
            "job_id": waiver.job_id,
            "status": waiver.status.value,
            "auto_approve": auto_approve,
            "expires_at": waiver.expires_at.isoformat() if waiver.expires_at else None,
        },
    )
    return _to_read(waiver)


@router.get("/{waiver_id}", response_model=ComplianceWaiverRead)
async def get_compliance_waiver(
    waiver_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(*_READ_ROLES)),
) -> ComplianceWaiverRead:
    waiver = await get_waiver_or_404(db, waiver_id)
    assert_can_access(user, waiver.owner_sub, detail="Waiver not found")
    return _to_read(waiver)


@router.patch("/{waiver_id}", response_model=ComplianceWaiverRead)
async def update_compliance_waiver(
    waiver_id: int,
    data: ComplianceWaiverUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(*_WRITE_ROLES)),
) -> ComplianceWaiverRead:
    waiver = await get_waiver_or_404(db, waiver_id)
    assert_can_access(user, waiver.owner_sub, detail="Waiver not found")
    if waiver.status not in (WaiverStatus.PENDING, WaiverStatus.APPROVED) or not waiver.is_active:
        raise HTTPException(status_code=400, detail="Only pending or approved waivers can be updated")

    if data.reason is not None:
        waiver.reason = data.reason.strip()
    if data.expires_at is not None:
        waiver.expires_at = data.expires_at

    await db.flush()
    await db.refresh(waiver)
    await log_audit_event(
        db,
        request,
        user,
        action="waiver.update",
        resource_type="compliance_waiver",
        resource_id=waiver.id,
        resource_name=waiver.rule_tech_name,
        metadata={"expires_at": waiver.expires_at.isoformat() if waiver.expires_at else None},
    )
    return _to_read(waiver)


@router.post("/{waiver_id}/approve", response_model=ComplianceWaiverRead)
async def approve_compliance_waiver(
    waiver_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(*_APPROVE_ROLES)),
) -> ComplianceWaiverRead:
    waiver = await get_waiver_or_404(db, waiver_id)
    transition_approve(waiver, user)
    await db.flush()
    await db.refresh(waiver)
    await log_audit_event(
        db,
        request,
        user,
        action="waiver.approve",
        resource_type="compliance_waiver",
        resource_id=waiver.id,
        resource_name=waiver.rule_tech_name,
        metadata={"approved_by": waiver.approved_by},
    )
    return _to_read(waiver)


@router.post("/{waiver_id}/reject", response_model=ComplianceWaiverRead)
async def reject_compliance_waiver(
    waiver_id: int,
    data: ComplianceWaiverReject,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(*_APPROVE_ROLES)),
) -> ComplianceWaiverRead:
    waiver = await get_waiver_or_404(db, waiver_id)
    transition_reject(waiver, user, data.reason)
    await db.flush()
    await db.refresh(waiver)
    await log_audit_event(
        db,
        request,
        user,
        action="waiver.reject",
        resource_type="compliance_waiver",
        resource_id=waiver.id,
        resource_name=waiver.rule_tech_name,
        metadata={"rejected_by": waiver.rejected_by, "reason": data.reason},
        outcome="failed",
    )
    return _to_read(waiver)


@router.post("/{waiver_id}/revoke", response_model=ComplianceWaiverRead)
async def revoke_compliance_waiver(
    waiver_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(*_APPROVE_ROLES)),
) -> ComplianceWaiverRead:
    waiver = await get_waiver_or_404(db, waiver_id)
    transition_revoke(waiver, user)
    await db.flush()
    await db.refresh(waiver)
    await log_audit_event(
        db,
        request,
        user,
        action="waiver.revoke",
        resource_type="compliance_waiver",
        resource_id=waiver.id,
        resource_name=waiver.rule_tech_name,
        outcome="failed",
    )
    return _to_read(waiver)


@router.delete("/{waiver_id}", status_code=204)
async def delete_compliance_waiver(
    waiver_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(*_WRITE_ROLES)),
) -> None:
    waiver = await get_waiver_or_404(db, waiver_id)
    assert_can_access(user, waiver.owner_sub, detail="Waiver not found")
    rule_name = waiver.rule_tech_name
    await log_audit_event(
        db,
        request,
        user,
        action="waiver.delete",
        resource_type="compliance_waiver",
        resource_id=waiver.id,
        resource_name=rule_name,
        metadata={"status": waiver.status.value, "profile_id": waiver.profile_id},
    )
    await db.delete(waiver)
    await db.flush()
