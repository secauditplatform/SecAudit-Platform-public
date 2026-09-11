from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import AuthUser, require_roles
from app.core.config import settings
from app.core.database import get_db
from app.models import UserRole
from app.core.secrets import encrypt_secret
from app.models import Credential, Host
from app.schemas import CredentialCreate, CredentialRead, CredentialUpdate
from app.services.audit_flow import sweep_orphaned_ephemeral_credentials
from app.services.audit_log import log_audit_event
from app.services.object_rbac import (
    apply_credential_list_scope,
    assert_can_access,
    assert_credential_visible,
    assign_owner,
)

router = APIRouter()


def _credential_to_read(credential: Credential) -> CredentialRead:
    return CredentialRead(
        id=credential.id,
        name=credential.name,
        credential_type=credential.credential_type,
        username=credential.username,
        service_username=credential.service_username,
        description=credential.description,
        has_service_secret=bool(credential.encrypted_service_secret),
        created_at=credential.created_at,
    )


@router.get("", response_model=list[CredentialRead])
async def list_credentials(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> list[CredentialRead]:
    await sweep_orphaned_ephemeral_credentials(db)
    stmt = apply_credential_list_scope(
        select(Credential).where(Credential.is_ephemeral.is_(False)).order_by(Credential.name),
        user,
    )
    result = await db.execute(stmt)
    items = [_credential_to_read(c) for c in result.scalars().all()]
    await log_audit_event(
        db,
        request,
        user,
        action="credential.metadata.view",
        resource_type="credential",
        metadata={"result_count": len(items)},
    )
    return items


@router.post("", response_model=CredentialRead, status_code=201)
async def create_credential(
    data: CredentialCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> CredentialRead:
    existing = await db.execute(select(Credential).where(Credential.name == data.name))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Credential with this name already exists")

    credential = Credential(
        name=data.name,
        credential_type=data.credential_type,
        username=data.username,
        encrypted_secret=encrypt_secret(data.secret, settings),
        encrypted_key_passphrase=(
            encrypt_secret(data.key_passphrase, settings) if data.key_passphrase else None
        ),
        service_username=data.service_username,
        encrypted_service_secret=(
            encrypt_secret(data.service_secret, settings) if data.service_secret else None
        ),
        description=data.description,
    )
    assign_owner(credential, user)
    db.add(credential)
    await db.flush()
    await db.refresh(credential)
    await log_audit_event(
        db,
        request,
        user,
        action="credential.create",
        resource_type="credential",
        resource_id=credential.id,
        resource_name=credential.name,
    )
    return _credential_to_read(credential)


@router.get("/{credential_id}", response_model=CredentialRead)
async def get_credential(
    credential_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> CredentialRead:
    credential = await assert_credential_visible(db, user, credential_id)
    await log_audit_event(
        db,
        request,
        user,
        action="credential.metadata.view",
        resource_type="credential",
        resource_id=credential.id,
        resource_name=credential.name,
    )
    return _credential_to_read(credential)


@router.patch("/{credential_id}", response_model=CredentialRead)
async def update_credential(
    credential_id: int,
    data: CredentialUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> CredentialRead:
    credential = await assert_credential_visible(db, user, credential_id)
    assert_can_access(user, credential.owner_sub, detail="Credential not found")

    if data.name is not None and data.name != credential.name:
        existing = await db.execute(select(Credential).where(Credential.name == data.name))
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Credential with this name already exists")
        credential.name = data.name

    if data.credential_type is not None:
        credential.credential_type = data.credential_type
    if data.username is not None:
        credential.username = data.username
    if data.description is not None:
        credential.description = data.description
    if data.secret:
        credential.encrypted_secret = encrypt_secret(data.secret, settings)
    if data.key_passphrase is not None:
        credential.encrypted_key_passphrase = (
            encrypt_secret(data.key_passphrase, settings) if data.key_passphrase else None
        )
    if data.service_username is not None:
        credential.service_username = data.service_username or None
    if data.service_secret is not None:
        credential.encrypted_service_secret = (
            encrypt_secret(data.service_secret, settings) if data.service_secret else None
        )

    await db.flush()
    await db.refresh(credential)
    await log_audit_event(
        db,
        request,
        user,
        action="credential.update",
        resource_type="credential",
        resource_id=credential.id,
        resource_name=credential.name,
    )
    return _credential_to_read(credential)


@router.delete("/{credential_id}", status_code=204)
async def delete_credential(
    credential_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> None:
    credential = await assert_credential_visible(db, user, credential_id)
    assert_can_access(user, credential.owner_sub, detail="Credential not found")

    linked_hosts = await db.execute(select(Host).where(Host.credential_id == credential_id))
    for host in linked_hosts.scalars().all():
        host.credential_id = None

    credential_name = credential.name
    await db.delete(credential)
    await log_audit_event(
        db,
        request,
        user,
        action="credential.delete",
        resource_type="credential",
        resource_id=credential_id,
        resource_name=credential_name,
    )
