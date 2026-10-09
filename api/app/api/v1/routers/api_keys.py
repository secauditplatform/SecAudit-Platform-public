"""Admin CRUD for scoped service-account API keys."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import AuthUser, require_roles
from app.core.database import get_db
from app.models import ApiKey, UserRole
from app.schemas import ApiKeyCreate, ApiKeyCreated, ApiKeyRead, ApiKeyUpdate
from app.services.api_keys import (
    generate_api_key_material,
    get_api_key_or_404,
    normalize_scopes,
)
from app.services.audit_log import log_audit_event

router = APIRouter()


def _to_read(row: ApiKey) -> ApiKeyRead:
    return ApiKeyRead.model_validate(row)


@router.get("", response_model=list[ApiKeyRead])
async def list_api_keys(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> list[ApiKeyRead]:
    result = await db.execute(select(ApiKey).order_by(ApiKey.name))
    return [_to_read(row) for row in result.scalars().all()]


@router.post("", response_model=ApiKeyCreated, status_code=201)
async def create_api_key(
    data: ApiKeyCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> ApiKeyCreated:
    scopes = normalize_scopes(list(data.scopes))
    existing = await db.execute(select(ApiKey).where(ApiKey.name == data.name.strip()))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="API key name already exists")

    if data.expires_at is not None and data.expires_at <= datetime.now(UTC):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="expires_at must be in the future")

    prefix, token, key_hash = generate_api_key_material()
    row = ApiKey(
        name=data.name.strip(),
        key_prefix=prefix,
        key_hash=key_hash,
        scopes=scopes,
        created_by=actor.username,
        expires_at=data.expires_at,
        is_active=True,
    )
    db.add(row)
    await db.flush()
    await log_audit_event(
        db,
        request,
        actor,
        action="api_key.create",
        resource_type="api_key",
        resource_id=str(row.id),
        resource_name=row.name,
        metadata={"scopes": scopes, "key_prefix": prefix},
        durable=True,
    )
    await db.commit()
    await db.refresh(row)
    return ApiKeyCreated(**_to_read(row).model_dump(), secret=token)


@router.patch("/{key_id}", response_model=ApiKeyRead)
async def update_api_key(
    key_id: int,
    data: ApiKeyUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> ApiKeyRead:
    row = await get_api_key_or_404(db, key_id)
    updates = data.model_dump(exclude_unset=True)
    if "name" in updates and updates["name"] is not None:
        name = updates["name"].strip()
        clash = await db.execute(select(ApiKey).where(ApiKey.name == name, ApiKey.id != key_id))
        if clash.scalar_one_or_none():
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="API key name already exists")
        row.name = name
    if "scopes" in updates and updates["scopes"] is not None:
        row.scopes = normalize_scopes(list(updates["scopes"]))
    if "expires_at" in updates:
        expires = updates["expires_at"]
        if expires is not None and expires <= datetime.now(UTC):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="expires_at must be in the future")
        row.expires_at = expires
    if "is_active" in updates and updates["is_active"] is not None:
        row.is_active = bool(updates["is_active"])
        if row.is_active and row.revoked_at is not None:
            row.revoked_at = None
    await log_audit_event(
        db,
        request,
        actor,
        action="api_key.update",
        resource_type="api_key",
        resource_id=str(row.id),
        resource_name=row.name,
        metadata={"fields": sorted(updates.keys())},
        durable=True,
    )
    await db.commit()
    await db.refresh(row)
    return _to_read(row)


@router.post("/{key_id}/rotate", response_model=ApiKeyCreated)
async def rotate_api_key(
    key_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> ApiKeyCreated:
    row = await get_api_key_or_404(db, key_id)
    if row.revoked_at is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Cannot rotate a revoked API key")
    prefix, token, key_hash = generate_api_key_material()
    row.key_prefix = prefix
    row.key_hash = key_hash
    row.is_active = True
    await log_audit_event(
        db,
        request,
        actor,
        action="api_key.rotate",
        resource_type="api_key",
        resource_id=str(row.id),
        resource_name=row.name,
        metadata={"key_prefix": prefix},
        durable=True,
    )
    await db.commit()
    await db.refresh(row)
    return ApiKeyCreated(**_to_read(row).model_dump(), secret=token)


@router.post("/{key_id}/revoke", response_model=ApiKeyRead)
async def revoke_api_key(
    key_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> ApiKeyRead:
    row = await get_api_key_or_404(db, key_id)
    row.is_active = False
    row.revoked_at = datetime.now(UTC)
    await log_audit_event(
        db,
        request,
        actor,
        action="api_key.revoke",
        resource_type="api_key",
        resource_id=str(row.id),
        resource_name=row.name,
        durable=True,
    )
    await db.commit()
    await db.refresh(row)
    return _to_read(row)


@router.delete("/{key_id}", status_code=204, response_class=Response)
async def delete_api_key(
    key_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    actor: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> Response:
    row = await get_api_key_or_404(db, key_id)
    name = row.name
    await db.delete(row)
    await log_audit_event(
        db,
        request,
        actor,
        action="api_key.delete",
        resource_type="api_key",
        resource_id=str(key_id),
        resource_name=name,
        durable=True,
    )
    await db.commit()
    return Response(status_code=204)
