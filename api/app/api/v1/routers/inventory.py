from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from secaudit_core.inventory_scan_state import request_scan_cancel

from app.core.auth import AuthUser, require_roles
from app.core.roles import require_operate
from app.core.config import settings
from app.core.database import get_db
from app.models import InventoryScan, JobStatus, UserRole
from app.schemas import InventoryScanCreate, InventoryScanDetail, InventoryScanRead
from app.services.dispatch import cancel_active_run, commit_and_try_dispatch, enqueue_run_dispatch
from app.services.inventory_scan import (
    encode_nmap_flags,
    get_scan_detail,
    validate_nmap_flags,
    validate_scan_target,
)
from app.services.object_rbac import apply_owner_scope, assert_can_access, assign_owner

router = APIRouter()


@router.get("/scans", response_model=list[InventoryScanRead])
async def list_inventory_scans(
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_operate),
) -> list[InventoryScanRead]:
    stmt = select(InventoryScan).order_by(InventoryScan.created_at.desc()).limit(50)
    stmt = apply_owner_scope(stmt, InventoryScan.owner_sub, user)
    result = await db.execute(stmt)
    return [InventoryScanRead.model_validate(s) for s in result.scalars().all()]


@router.post("/scans", response_model=InventoryScanRead, status_code=201)
async def start_inventory_scan(
    data: InventoryScanCreate,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> InventoryScanRead:
    try:
        target = validate_scan_target(data.target)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    custom_args: list[str] | None = None
    if data.nmap_flags and data.nmap_flags.strip():
        try:
            custom_args = validate_nmap_flags(data.nmap_flags)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    scan = InventoryScan(
        target=target,
        status=JobStatus.PENDING,
        nmap_flags=encode_nmap_flags(custom_args),
    )
    assign_owner(scan, user)
    db.add(scan)
    await db.flush()
    await db.refresh(scan)
    scan_id = scan.id

    outbox = await enqueue_run_dispatch(
        db,
        task_name="app.tasks.inventory.run_inventory_scan_task",
        args=[scan_id],
        queue="inventory",
        callback_kind="inventory_scan",
        callback_ref_id=scan_id,
        correlation={"started_by_sub": user.sub, "scan_id": scan_id},
    )
    await commit_and_try_dispatch(db, outbox_id=outbox.id, pending_entity=scan)

    if scan.status == JobStatus.FAILED:
        raise HTTPException(status_code=503, detail=scan.error_message or "Failed to dispatch inventory scan")
    scan = await db.get(InventoryScan, scan_id)
    return InventoryScanRead.model_validate(scan)


@router.get("/scans/{scan_id}", response_model=InventoryScanDetail)
async def get_inventory_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_operate),
) -> InventoryScanDetail:
    scan = await get_scan_detail(db, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    assert_can_access(user, scan.owner_sub, detail="Scan not found")
    return InventoryScanDetail.model_validate(scan)


@router.post("/scans/{scan_id}/stop", response_model=InventoryScanRead)
async def stop_inventory_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> InventoryScanRead:
    scan = await db.get(InventoryScan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    assert_can_access(user, scan.owner_sub, detail="Scan not found")

    if scan.status not in (JobStatus.PENDING, JobStatus.RUNNING):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot stop scan in status '{scan.status.value}'",
        )

    if not await cancel_active_run(db, InventoryScan, scan_id):
        await db.refresh(scan)
        raise HTTPException(
            status_code=409,
            detail=f"Cannot stop scan in status '{scan.status.value}'",
        )
    request_scan_cancel(settings.redis_url, scan_id)
    await db.flush()
    await db.refresh(scan)
    return InventoryScanRead.model_validate(scan)


@router.delete("/scans/{scan_id}", status_code=204)
async def delete_inventory_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> None:
    scan = await db.get(InventoryScan, scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    assert_can_access(user, scan.owner_sub, detail="Scan not found")

    if scan.status in (JobStatus.PENDING, JobStatus.RUNNING):
        request_scan_cancel(settings.redis_url, scan_id)

    await db.delete(scan)
