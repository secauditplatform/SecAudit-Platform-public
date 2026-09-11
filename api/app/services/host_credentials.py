"""Sync host_credentials junction rows with hosts.credential_id."""

from __future__ import annotations

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import AuthUser
from app.models import Credential, Host, HostCredentialLink
from app.services.object_rbac import assert_credential_attachable
from fastapi import HTTPException


def _credential_ids_from_host(host: Host) -> list[int]:
    if host.credential_links:
        ordered = sorted(host.credential_links, key=lambda item: item.sort_order)
        return [link.credential_id for link in ordered]
    if host.credential_id is not None:
        return [host.credential_id]
    return []


async def _validate_credentials(
    db: AsyncSession,
    user: AuthUser,
    credential_ids: list[int],
) -> list[Credential]:
    if not credential_ids:
        return []
    unique_ids = list(dict.fromkeys(credential_ids))
    ordered: list[Credential] = []
    for credential_id in unique_ids:
        cred = await db.get(Credential, credential_id)
        if cred is None:
            raise HTTPException(status_code=404, detail="Credential not found")
        assert_credential_attachable(user, cred.owner_sub)
        ordered.append(cred)
    return ordered


async def replace_host_credentials(
    db: AsyncSession,
    host: Host,
    user: AuthUser,
    credential_ids: list[int],
) -> None:
    credentials = await _validate_credentials(db, user, credential_ids)
    await db.execute(delete(HostCredentialLink).where(HostCredentialLink.host_id == host.id))
    for index, cred in enumerate(credentials):
        db.add(
            HostCredentialLink(
                host_id=host.id,
                credential_id=cred.id,
                sort_order=index,
            )
        )
    host.credential_id = credentials[0].id if credentials else None


async def link_host_credential(
    db: AsyncSession,
    host: Host,
    user: AuthUser,
    credential_id: int,
) -> None:
    current_ids = _credential_ids_from_host(host)
    if credential_id in current_ids:
        return
    await replace_host_credentials(db, host, user, [*current_ids, credential_id])


async def unlink_host_credential(
    db: AsyncSession,
    host: Host,
    user: AuthUser,
    credential_id: int,
) -> None:
    current_ids = [item for item in _credential_ids_from_host(host) if item != credential_id]
    await replace_host_credentials(db, host, user, current_ids)
