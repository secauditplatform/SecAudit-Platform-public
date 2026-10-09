"""Read-only AD/LDAP computer discovery."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from secaudit_core.directory_discovery import (
    DirectoryBind,
    DirectoryDiscoveryError,
    normalize_directory_endpoint,
    probe_directory,
)

from app.core.auth import AuthUser
from app.core.config import settings
from app.core.roles import require_inventory_scan, require_operate
from app.core.database import get_db
from app.core.secrets import decrypt_secret, encrypt_secret
from app.models import DirectorySource, DirectorySync, JobStatus
from app.schemas import (
    DirectoryProbeRead,
    DirectorySourceCreate,
    DirectorySourceRead,
    DirectorySourceTest,
    DirectorySourceUpdate,
    DirectorySyncRead,
)
from app.services.dispatch import commit_and_try_dispatch, enqueue_run_dispatch
from app.services.object_rbac import apply_owner_scope, assert_can_access, assign_owner

router = APIRouter()


def _validated_endpoint(
    *,
    server: str,
    port: int,
    use_ssl: bool,
    start_tls: bool,
    base_dn: str,
    bind_dn: str,
) -> tuple[str, int, str, str, bool]:
    try:
        return normalize_directory_endpoint(
            server=server,
            port=port,
            use_ssl=use_ssl,
            start_tls=start_tls,
            base_dn=base_dn,
            bind_dn=bind_dn,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _password_or_422(password: str | None) -> str:
    if password is None or not password.strip():
        raise HTTPException(status_code=422, detail="Bind password is required")
    if "\x00" in password:
        raise HTTPException(status_code=422, detail="Bind password contains unsupported characters")
    return password


@router.get("/sources", response_model=list[DirectorySourceRead])
async def list_directory_sources(
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_operate),
) -> list[DirectorySource]:
    stmt = select(DirectorySource).order_by(DirectorySource.created_at.desc()).limit(50)
    stmt = apply_owner_scope(stmt, DirectorySource.owner_sub, user)
    result = await db.execute(stmt)
    return list(result.scalars().all())


@router.post("/sources", response_model=DirectorySourceRead, status_code=201)
async def create_directory_source(
    data: DirectorySourceCreate,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_inventory_scan),
) -> DirectorySource:
    password = _password_or_422(data.bind_password)
    server, port, base_dn, bind_dn, start_tls = _validated_endpoint(
        server=data.server,
        port=data.port,
        use_ssl=data.use_ssl,
        start_tls=data.start_tls,
        base_dn=data.base_dn,
        bind_dn=data.bind_dn,
    )
    source = DirectorySource(
        name=data.name.strip(),
        server=server,
        port=port,
        use_ssl=data.use_ssl,
        start_tls=start_tls,
        verify_tls=data.verify_tls,
        base_dn=base_dn,
        bind_dn=bind_dn,
        encrypted_bind_password=encrypt_secret(password, settings),
        enabled_only=data.enabled_only,
        map_ou_to_site=data.map_ou_to_site,
        is_active=data.is_active,
    )
    assign_owner(source, user)
    db.add(source)
    await db.commit()
    await db.refresh(source)
    return source


@router.patch("/sources/{source_id}", response_model=DirectorySourceRead)
async def update_directory_source(
    source_id: int,
    data: DirectorySourceUpdate,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_inventory_scan),
) -> DirectorySource:
    source = await _get_source(db, source_id, user)
    payload = data.model_dump(exclude_unset=True)
    password = payload.pop("bind_password", None)
    server = payload.get("server", source.server)
    port = payload.get("port", source.port)
    use_ssl = payload.get("use_ssl", source.use_ssl)
    start_tls = payload.get("start_tls", source.start_tls)
    base_dn = payload.get("base_dn", source.base_dn)
    bind_dn = payload.get("bind_dn", source.bind_dn)
    server, port, base_dn, bind_dn, start_tls = _validated_endpoint(
        server=server,
        port=port,
        use_ssl=use_ssl,
        start_tls=start_tls,
        base_dn=base_dn,
        bind_dn=bind_dn,
    )
    source.server = server
    source.port = port
    source.use_ssl = use_ssl
    source.start_tls = start_tls
    source.base_dn = base_dn
    source.bind_dn = bind_dn
    if "name" in payload and payload["name"] is not None:
        source.name = payload["name"].strip()
    if "verify_tls" in payload:
        source.verify_tls = bool(payload["verify_tls"])
    if "enabled_only" in payload:
        source.enabled_only = bool(payload["enabled_only"])
    if "map_ou_to_site" in payload:
        source.map_ou_to_site = bool(payload["map_ou_to_site"])
    if "is_active" in payload:
        source.is_active = bool(payload["is_active"])
    if password is not None and password.strip():
        source.encrypted_bind_password = encrypt_secret(_password_or_422(password), settings)
    await db.commit()
    await db.refresh(source)
    return source


@router.delete("/sources/{source_id}", status_code=204, response_model=None)
async def delete_directory_source(
    source_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_inventory_scan),
) -> None:
    source = await _get_source(db, source_id, user)
    await db.delete(source)
    await db.commit()


@router.post("/sources/test", response_model=DirectoryProbeRead)
async def test_directory_source(
    data: DirectorySourceTest,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_inventory_scan),
) -> DirectoryProbeRead:
    password = data.bind_password.strip() if data.bind_password else ""
    if not password and data.source_id is not None:
        source = await _get_source(db, data.source_id, user)
        try:
            password = decrypt_secret(source.encrypted_bind_password, settings)
        except Exception as exc:
            raise HTTPException(status_code=422, detail="Stored bind password could not be read") from exc
    password = _password_or_422(password or None)
    server, port, base_dn, bind_dn, start_tls = _validated_endpoint(
        server=data.server,
        port=data.port,
        use_ssl=data.use_ssl,
        start_tls=data.start_tls,
        base_dn=data.base_dn,
        bind_dn=data.bind_dn,
    )
    bind = DirectoryBind(
        server=server,
        port=port,
        use_ssl=data.use_ssl,
        start_tls=start_tls,
        verify_tls=data.verify_tls,
        base_dn=base_dn,
        bind_dn=bind_dn,
        password=password,
        enabled_only=data.enabled_only,
    )
    try:
        result = await asyncio.to_thread(probe_directory, bind)
    except DirectoryDiscoveryError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return DirectoryProbeRead(
        computers=result.computers,
        sample=result.sample,
        truncated=result.truncated,
    )


@router.post("/sources/{source_id}/sync", response_model=DirectorySyncRead, status_code=201)
async def start_directory_sync(
    source_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_inventory_scan),
) -> DirectorySync:
    source = await _get_source(db, source_id, user)
    if not source.is_active:
        raise HTTPException(status_code=409, detail="Directory source is disabled")
    active = await db.execute(
        select(DirectorySync.id).where(
            DirectorySync.source_id == source.id,
            DirectorySync.status.in_((JobStatus.PENDING, JobStatus.RUNNING)),
        )
    )
    if active.scalar_one_or_none() is not None:
        raise HTTPException(status_code=409, detail="Directory import is already running")
    sync = DirectorySync(source_id=source.id, status=JobStatus.PENDING)
    assign_owner(sync, user)
    db.add(sync)
    await db.flush()
    await db.refresh(sync)
    sync_id = sync.id
    outbox = await enqueue_run_dispatch(
        db,
        task_name="app.tasks.directory.run_directory_sync_task",
        args=[sync_id],
        queue="inventory",
        callback_kind="directory_sync",
        callback_ref_id=sync_id,
        correlation={"started_by_sub": user.sub, "sync_id": sync_id, "source_id": source.id},
    )
    await commit_and_try_dispatch(db, outbox_id=outbox.id, pending_entity=sync)
    sync = await db.get(DirectorySync, sync_id)
    if sync is None:
        raise HTTPException(status_code=404, detail="Directory import not found")
    if sync.status == JobStatus.FAILED:
        raise HTTPException(status_code=503, detail=sync.error_message or "Failed to dispatch directory import")
    return sync


@router.get("/syncs", response_model=list[DirectorySyncRead])
async def list_directory_syncs(
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_operate),
) -> list[DirectorySync]:
    stmt = select(DirectorySync).order_by(DirectorySync.created_at.desc()).limit(50)
    stmt = apply_owner_scope(stmt, DirectorySync.owner_sub, user)
    result = await db.execute(stmt)
    return list(result.scalars().all())


async def _get_source(db: AsyncSession, source_id: int, user: AuthUser) -> DirectorySource:
    source = await db.get(DirectorySource, source_id)
    if source is None:
        raise HTTPException(status_code=404, detail="Directory source not found")
    assert_can_access(user, source.owner_sub, detail="Directory source not found")
    return source
