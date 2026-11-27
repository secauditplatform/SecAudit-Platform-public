"""CRUD for remediation maintenance windows."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import AuthUser, require_roles
from app.core.database import get_db
from app.models import MaintenanceWindow, UserRole
from app.schemas import MaintenanceWindowCreate, MaintenanceWindowRead, MaintenanceWindowUpdate
from app.services.audit_log import log_audit_event

router = APIRouter()


@router.get("", response_model=list[MaintenanceWindowRead])
async def list_windows(
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN, UserRole.OPERATOR, UserRole.AUDITOR)),
) -> list[MaintenanceWindowRead]:
    rows = (
        await db.execute(select(MaintenanceWindow).order_by(MaintenanceWindow.id.asc()))
    ).scalars().all()
    return [MaintenanceWindowRead.model_validate(row) for row in rows]


@router.post("", response_model=MaintenanceWindowRead, status_code=201)
async def create_window(
    data: MaintenanceWindowCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> MaintenanceWindowRead:
    row = MaintenanceWindow(**data.model_dump())
    db.add(row)
    await db.flush()
    await log_audit_event(
        db,
        request,
        user,
        action="maintenance_window.create",
        resource_type="maintenance_window",
        resource_id=row.id,
    )
    await db.commit()
    await db.refresh(row)
    return MaintenanceWindowRead.model_validate(row)


@router.put("/{window_id}", response_model=MaintenanceWindowRead)
async def update_window(
    window_id: int,
    data: MaintenanceWindowUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> MaintenanceWindowRead:
    row = await db.get(MaintenanceWindow, window_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Maintenance window not found")
    for key, value in data.model_dump(exclude_unset=True).items():
        setattr(row, key, value)
    await log_audit_event(
        db,
        request,
        user,
        action="maintenance_window.update",
        resource_type="maintenance_window",
        resource_id=row.id,
    )
    await db.commit()
    await db.refresh(row)
    return MaintenanceWindowRead.model_validate(row)


@router.delete("/{window_id}", status_code=204, response_class=Response)
async def delete_window(
    window_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> Response:
    row = await db.get(MaintenanceWindow, window_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Maintenance window not found")
    await db.delete(row)
    await log_audit_event(
        db,
        request,
        user,
        action="maintenance_window.delete",
        resource_type="maintenance_window",
        resource_id=window_id,
    )
    await db.commit()
    return Response(status_code=204)
