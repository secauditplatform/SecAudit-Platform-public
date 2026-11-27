from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import AuthUser, require_roles
from app.core.config import settings
from app.core.database import get_db
from app.models import ComplianceWaiver, Host, UserRole, WaiverStatus
from app.schemas import (
    ComplianceWaiverApprove,
    ComplianceWaiverCreate,
    ComplianceWaiverRead,
    ComplianceWaiverReject,
    ComplianceWaiverUpdate,
    ComplianceWaiversBulkActionError,
    ComplianceWaiversBulkActionResult,
    ComplianceWaiversBulkApproveRequest,
    ComplianceWaiversBulkRejectRequest,
)
from app.services.audit_log import log_audit_event
from app.services.object_rbac import apply_waiver_scope, assert_can_access, operator_scope
from app.services.waivers import (
    actor_name,
    assert_job_scope,
    assert_profile_exists,
    bulk_transition,
    get_waiver_or_404,
    list_waivers,
    new_owner_sub,
    transition_approve,
    transition_reject,
    transition_reopen,
    transition_revoke,
)

router = APIRouter()

_READ_ROLES = (UserRole.ADMIN, UserRole.OPERATOR, UserRole.SECURITY_APPROVER)
_WRITE_ROLES = (UserRole.ADMIN, UserRole.OPERATOR)
_APPROVE_ROLES = (UserRole.ADMIN, UserRole.SECURITY_APPROVER)


def _to_read(waiver: ComplianceWaiver) -> ComplianceWaiverRead:
    return ComplianceWaiverRead.model_validate(waiver)


def _normalize_ticket(value: str | None) -> str | None:
    if value is None:
        return None
    ticket = value.strip()
    return ticket or None


def _scope_value(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip()
    if not cleaned:
        return None
    if len(cleaned) > 64:
        raise HTTPException(status_code=400, detail="Scope value is too long")
    return cleaned


async def _assert_waiver_visible(db, user: AuthUser, waiver: ComplianceWaiver) -> None:
    assert_can_access(user, waiver.owner_sub, detail="Waiver not found")
    if operator_scope(user) is None:
        return
    found = await db.execute(
        apply_waiver_scope(select(ComplianceWaiver.id).where(ComplianceWaiver.id == waiver.id), user)
    )
    if found.scalar_one_or_none() is None:
        raise HTTPException(status_code=404, detail="Waiver not found")


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

    auto_approve = bool(
        data.auto_approve and user.has_role(UserRole.ADMIN) and not settings.waiver_strict_four_eyes
    )
    now = datetime.now(UTC)
    change_ticket = _normalize_ticket(data.change_ticket)
    waiver = ComplianceWaiver(
        profile_id=data.profile_id,
        rule_tech_name=data.rule_tech_name.strip(),
        host_id=data.host_id,
        job_id=data.job_id,
        scope_site=_scope_value(data.scope_site),
        scope_environment=_scope_value(data.scope_environment),
        scope_tag=_scope_value(data.scope_tag),
        reason=data.reason.strip(),
        change_ticket=change_ticket,
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
            "change_ticket": waiver.change_ticket,
            "expires_at": waiver.expires_at.isoformat() if waiver.expires_at else None,
        },
    )
    return _to_read(waiver)


@router.post("/bulk/approve", response_model=ComplianceWaiversBulkActionResult)
async def bulk_approve_compliance_waivers(
    data: ComplianceWaiversBulkApproveRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(*_APPROVE_ROLES)),
) -> ComplianceWaiversBulkActionResult:
    if not data.waiver_ids:
        raise HTTPException(status_code=400, detail="waiver_ids is required")
    result = await bulk_transition(
        db,
        user,
        data.waiver_ids,
        action="approve",
        change_ticket=data.change_ticket,
    )
    if result["succeeded"]:
        await db.flush()
        await log_audit_event(
            db,
            request,
            user,
            action="waiver.bulk_approve",
            resource_type="compliance_waiver",
            metadata={
                "waiver_ids": result["succeeded"],
                "change_ticket": _normalize_ticket(data.change_ticket),
                "failed_count": len(result["failed"]),
            },
        )
    return ComplianceWaiversBulkActionResult(
        succeeded=result["succeeded"],
        failed=[ComplianceWaiversBulkActionError.model_validate(item) for item in result["failed"]],
    )


@router.post("/bulk/reject", response_model=ComplianceWaiversBulkActionResult)
async def bulk_reject_compliance_waivers(
    data: ComplianceWaiversBulkRejectRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(*_APPROVE_ROLES)),
) -> ComplianceWaiversBulkActionResult:
    if not data.waiver_ids:
        raise HTTPException(status_code=400, detail="waiver_ids is required")
    result = await bulk_transition(
        db,
        user,
        data.waiver_ids,
        action="reject",
        reason=data.reason,
    )
    if result["succeeded"]:
        await db.flush()
        await log_audit_event(
            db,
            request,
            user,
            action="waiver.bulk_reject",
            resource_type="compliance_waiver",
            metadata={
                "waiver_ids": result["succeeded"],
                "reason": data.reason,
                "failed_count": len(result["failed"]),
            },
            outcome="failed",
        )
    return ComplianceWaiversBulkActionResult(
        succeeded=result["succeeded"],
        failed=[ComplianceWaiversBulkActionError.model_validate(item) for item in result["failed"]],
    )


@router.get("/{waiver_id}", response_model=ComplianceWaiverRead)
async def get_compliance_waiver(
    waiver_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(*_READ_ROLES)),
) -> ComplianceWaiverRead:
    waiver = await get_waiver_or_404(db, waiver_id)
    await _assert_waiver_visible(db, user, waiver)
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
    await _assert_waiver_visible(db, user, waiver)
    if waiver.status not in (WaiverStatus.PENDING, WaiverStatus.APPROVED) or not waiver.is_active:
        raise HTTPException(status_code=400, detail="Only pending or approved waivers can be updated")

    before = {
        "reason": waiver.reason,
        "change_ticket": waiver.change_ticket,
        "expires_at": waiver.expires_at.isoformat() if waiver.expires_at else None,
    }
    changed: dict = {}
    if "reason" in data.model_fields_set and data.reason is not None:
        reason = data.reason.strip()
        if not reason:
            raise HTTPException(status_code=400, detail="reason is required")
        if reason != waiver.reason:
            changed["reason"] = reason
    if "change_ticket" in data.model_fields_set:
        ticket = _normalize_ticket(data.change_ticket)
        if ticket != waiver.change_ticket:
            changed["change_ticket"] = ticket
    if "expires_at" in data.model_fields_set and data.expires_at != waiver.expires_at:
        changed["expires_at"] = data.expires_at
    if waiver.status == WaiverStatus.APPROVED and changed and not user.has_role(UserRole.ADMIN):
        raise HTTPException(
            status_code=400,
            detail="Approved waiver cannot be changed. Reopen it for approval.",
        )
    if "reason" in changed:
        waiver.reason = changed["reason"]
    if "change_ticket" in changed:
        waiver.change_ticket = changed["change_ticket"]
    if "expires_at" in changed:
        waiver.expires_at = changed["expires_at"]

    await db.flush()
    await db.refresh(waiver)
    approved_edit = waiver.status == WaiverStatus.APPROVED and bool(changed)
    await log_audit_event(
        db,
        request,
        user,
        action="waiver.update_approved" if approved_edit else "waiver.update",
        resource_type="compliance_waiver",
        resource_id=waiver.id,
        resource_name=waiver.rule_tech_name,
        metadata={
            "before": before,
            "expires_at": waiver.expires_at.isoformat() if waiver.expires_at else None,
            "change_ticket": waiver.change_ticket,
            "reason": waiver.reason,
        },
    )
    return _to_read(waiver)


@router.post("/{waiver_id}/reopen", response_model=ComplianceWaiverRead)
async def reopen_compliance_waiver(
    waiver_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(*_WRITE_ROLES)),
) -> ComplianceWaiverRead:
    waiver = await get_waiver_or_404(db, waiver_id)
    await _assert_waiver_visible(db, user, waiver)
    transition_reopen(waiver)
    await db.flush()
    await db.refresh(waiver)
    await log_audit_event(
        db,
        request,
        user,
        action="waiver.reopen",
        resource_type="compliance_waiver",
        resource_id=waiver.id,
        resource_name=waiver.rule_tech_name,
    )
    return _to_read(waiver)


@router.post("/{waiver_id}/approve", response_model=ComplianceWaiverRead)
async def approve_compliance_waiver(
    waiver_id: int,
    request: Request,
    data: ComplianceWaiverApprove | None = None,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(*_APPROVE_ROLES)),
) -> ComplianceWaiverRead:
    waiver = await get_waiver_or_404(db, waiver_id)
    payload = data or ComplianceWaiverApprove()
    transition_approve(waiver, user, change_ticket=payload.change_ticket)
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
        metadata={"approved_by": waiver.approved_by, "change_ticket": waiver.change_ticket},
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
    await _assert_waiver_visible(db, user, waiver)
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
