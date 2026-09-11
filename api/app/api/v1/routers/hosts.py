from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import delete, distinct, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.auth import AuthUser, require_roles
from app.core.roles import require_reports
from app.core.blocking import run_blocking
from app.core.config import settings
from app.core.database import get_db
from app.models import (
    CheckResult,
    ComplianceWaiver,
    Credential,
    Host,
    HostCredentialLink,
    HostTag,
    HostTagLink,
    InventoryScanResult,
    Job,
    JobHost,
    JobRun,
    JobStatus,
    JobTemplateHost,
    RemediationJob,
    RemediationJobHost,
    RemediationResult,
    RemediationRun,
    UserRole,
)
from app.pagination import paginate_scalars, pagination_params
from app.schemas import (
    HostBulkDeleteConflict,
    HostBulkDeleteRequest,
    HostBulkDeleteResponse,
    HostCreate,
    HostCredentialLinkRequest,
    HostTagAssignRequest,
    HostTagRead,
    HostRead,
    HostLinkedCredentialRead,
    HostSshFingerprintScanResponse,
    HostUpdate,
    PaginatedResponse,
)
from app.services.audit_log import log_audit_event
from app.services.host_credentials import (
    link_host_credential,
    replace_host_credentials,
    unlink_host_credential,
)
from app.services.object_rbac import (
    apply_owner_scope,
    assert_can_access,
    assert_credential_attachable,
    assert_hosts_accessible,
    assign_owner,
)

router = APIRouter()

_HOST_LOAD_OPTIONS = (
    selectinload(Host.tags).selectinload(HostTagLink.tag),
    selectinload(Host.credential_links).selectinload(HostCredentialLink.credential),
    selectinload(Host.credential),
)

_HOST_NOT_FOUND = "Host not found"
_HOST_ACTIVE_RUN = "Host is included in an active run and cannot be deleted"
_HOST_DELETE_FAILED = "Host could not be deleted due to related data"


async def _host_has_active_runs(db: AsyncSession, host_id: int) -> bool:
    job_active = await db.execute(
        select(JobRun.id)
        .join(Job, JobRun.job_id == Job.id)
        .join(JobHost, JobHost.job_id == Job.id)
        .where(
            JobHost.host_id == host_id,
            JobRun.status.in_([JobStatus.PENDING, JobStatus.RUNNING]),
        )
        .limit(1)
    )
    if job_active.scalar_one_or_none():
        return True

    remediation_active = await db.execute(
        select(RemediationRun.id)
        .join(RemediationJob, RemediationRun.remediation_job_id == RemediationJob.id)
        .join(RemediationJobHost, RemediationJobHost.remediation_job_id == RemediationJob.id)
        .where(
            RemediationJobHost.host_id == host_id,
            RemediationRun.status.in_([JobStatus.PENDING, JobStatus.RUNNING]),
        )
        .limit(1)
    )
    return remediation_active.scalar_one_or_none() is not None


async def _cleanup_host_references(db: AsyncSession, host_id: int) -> None:
    await db.execute(delete(CheckResult).where(CheckResult.host_id == host_id))
    await db.execute(delete(RemediationResult).where(RemediationResult.host_id == host_id))
    await db.execute(delete(JobHost).where(JobHost.host_id == host_id))
    await db.execute(delete(RemediationJobHost).where(RemediationJobHost.host_id == host_id))
    await db.execute(delete(JobTemplateHost).where(JobTemplateHost.host_id == host_id))
    await db.execute(delete(HostTagLink).where(HostTagLink.host_id == host_id))

    waivers = await db.execute(select(ComplianceWaiver).where(ComplianceWaiver.host_id == host_id))
    for waiver in waivers.scalars().all():
        waiver.host_id = None

    scan_results = await db.execute(
        select(InventoryScanResult).where(InventoryScanResult.host_id == host_id)
    )
    for result in scan_results.scalars().all():
        result.host_id = None


async def _delete_host_if_allowed(host_id: int, db: AsyncSession, user: AuthUser) -> str | None:
    """Delete host when allowed. Returns error detail or None on success."""
    host = await db.get(Host, host_id)
    if not host:
        return _HOST_NOT_FOUND

    try:
        assert_can_access(user, host.owner_sub, detail=_HOST_NOT_FOUND)
    except HTTPException:
        return _HOST_NOT_FOUND

    if await _host_has_active_runs(db, host_id):
        return _HOST_ACTIVE_RUN

    await _cleanup_host_references(db, host_id)
    await db.delete(host)
    await db.flush()
    return None


def _host_to_read(host: Host) -> HostRead:
    if host.credential_links:
        ordered_links = sorted(host.credential_links, key=lambda item: item.sort_order)
        credential_ids = [link.credential_id for link in ordered_links]
        linked_credentials = [
            HostLinkedCredentialRead(
                id=link.credential.id,
                name=link.credential.name,
                credential_type=link.credential.credential_type,
                username=link.credential.username,
            )
            for link in ordered_links
            if link.credential is not None
        ]
    elif host.credential_id is not None and host.credential is not None:
        credential_ids = [host.credential_id]
        linked_credentials = [
            HostLinkedCredentialRead(
                id=host.credential.id,
                name=host.credential.name,
                credential_type=host.credential.credential_type,
                username=host.credential.username,
            )
        ]
    else:
        credential_ids = []
        linked_credentials = []

    return HostRead(
        id=host.id,
        name=host.name,
        hostname=host.hostname,
        port=host.port,
        os_type=host.os_type,
        credential_id=host.credential_id,
        credential_ids=credential_ids,
        linked_credentials=linked_credentials,
        is_active=host.is_active,
        created_at=host.created_at,
        owner_sub=host.owner_sub,
        ssh_host_key_fingerprint=host.ssh_host_key_fingerprint,
        tags=sorted(link.tag.name for link in host.tags if link.tag),
    )


async def _load_host(db: AsyncSession, host_id: int) -> Host | None:
    result = await db.execute(
        select(Host).options(*_HOST_LOAD_OPTIONS).where(Host.id == host_id)
    )
    return result.scalar_one_or_none()


@router.get("", response_model=PaginatedResponse[HostRead])
async def list_hosts(
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_reports),
    page: tuple[int, int] = Depends(pagination_params),
    tag: list[str] = Query(default=[]),
    active_only: bool = Query(default=False),
    search: str | None = Query(default=None),
) -> PaginatedResponse[HostRead]:
    offset, limit = page
    stmt = select(Host).options(*_HOST_LOAD_OPTIONS)
    stmt = apply_owner_scope(stmt, Host.owner_sub, user)
    stmt = stmt.where(Host.is_ephemeral.is_(False))
    if active_only:
        stmt = stmt.where(Host.is_active.is_(True))
    if search:
        q = f"%{search.strip()}%"
        stmt = stmt.where((Host.name.ilike(q)) | (Host.hostname.ilike(q)))
    if tag:
        tag_stmt = (
            select(distinct(HostTagLink.host_id))
            .join(HostTag, HostTag.id == HostTagLink.tag_id)
            .where(HostTag.name.in_(tag))
        )
        stmt = stmt.where(Host.id.in_(tag_stmt))
    stmt = stmt.order_by(Host.name)
    hosts, total = await paginate_scalars(db, stmt, offset=offset, limit=limit)
    return PaginatedResponse(
        items=[_host_to_read(h) for h in hosts],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.post("", response_model=HostRead, status_code=201)
async def create_host(
    data: HostCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> HostRead:
    if data.credential_id is not None:
        credential = await db.get(Credential, data.credential_id)
        if not credential:
            raise HTTPException(status_code=404, detail="Credential not found")
        assert_credential_attachable(user, credential.owner_sub)

    payload = data.model_dump(exclude={"credential_ids"})
    host = Host(**payload)
    assign_owner(host, user)
    db.add(host)
    await db.flush()
    credential_ids = data.credential_ids or (
        [data.credential_id] if data.credential_id is not None else []
    )
    if credential_ids:
        await replace_host_credentials(db, host, user, credential_ids)
    result = await db.execute(
        select(Host).options(*_HOST_LOAD_OPTIONS).where(Host.id == host.id)
    )
    await log_audit_event(
        db,
        request,
        user,
        action="host.create",
        resource_type="host",
        resource_id=host.id,
        resource_name=host.name,
    )
    return _host_to_read(result.scalar_one())


@router.post("/bulk-delete", response_model=HostBulkDeleteResponse)
async def bulk_delete_hosts(
    data: HostBulkDeleteRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> HostBulkDeleteResponse:
    deleted: list[int] = []
    conflicts: list[HostBulkDeleteConflict] = []

    for host_id in dict.fromkeys(data.host_ids):
        try:
            async with db.begin_nested():
                error = await _delete_host_if_allowed(host_id, db, user)
                if error:
                    conflicts.append(HostBulkDeleteConflict(host_id=host_id, detail=error))
                else:
                    deleted.append(host_id)
        except IntegrityError:
            conflicts.append(
                HostBulkDeleteConflict(host_id=host_id, detail=_HOST_DELETE_FAILED)
            )

    if deleted or conflicts:
        await log_audit_event(
            db,
            request,
            user,
            action="host.bulk_delete",
            resource_type="host",
            outcome="failed" if conflicts and not deleted else "success",
            metadata={"deleted_count": len(deleted), "conflict_count": len(conflicts)},
        )

    return HostBulkDeleteResponse(deleted=deleted, conflicts=conflicts)


@router.get("/tags", response_model=list[HostTagRead])
async def list_host_tags(
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_reports),
) -> list[HostTagRead]:
    stmt = (
        select(HostTag)
        .join(HostTagLink, HostTagLink.tag_id == HostTag.id)
        .join(Host, Host.id == HostTagLink.host_id)
    )
    stmt = apply_owner_scope(stmt, Host.owner_sub, user)
    stmt = stmt.distinct().order_by(HostTag.name)
    result = await db.execute(stmt)
    return [HostTagRead.model_validate(tag) for tag in result.scalars().all()]


@router.get("/{host_id}", response_model=HostRead)
async def get_host(
    host_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_reports),
) -> HostRead:
    host = await _load_host(db, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    assert_can_access(user, host.owner_sub, detail="Host not found")
    return _host_to_read(host)


@router.patch("/{host_id}", response_model=HostRead)
async def update_host(
    host_id: int,
    data: HostUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> HostRead:
    host = await _load_host(db, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    assert_can_access(user, host.owner_sub, detail="Host not found")

    updates = data.model_dump(exclude_unset=True)
    clear_ssh = updates.pop("clear_ssh_host_key", False)
    credential_ids = updates.pop("credential_ids", None)
    if clear_ssh:
        host.ssh_host_key_fingerprint = None
        host.ssh_known_hosts_entry = None
    updates.pop("ssh_host_key_fingerprint", None)

    if credential_ids is not None:
        await replace_host_credentials(db, host, user, credential_ids)
    elif "credential_id" in updates:
        credential_id = updates.pop("credential_id")
        if credential_id is None:
            await replace_host_credentials(db, host, user, [])
        else:
            await replace_host_credentials(db, host, user, [credential_id])

    for field, value in updates.items():
        setattr(host, field, value)

    await db.flush()
    host = await _load_host(db, host.id)
    assert host is not None
    await log_audit_event(
        db,
        request,
        user,
        action="host.update",
        resource_type="host",
        resource_id=host.id,
        resource_name=host.name,
    )
    return _host_to_read(host)


@router.post("/{host_id}/credentials", response_model=HostRead)
async def link_credential_to_host(
    host_id: int,
    data: HostCredentialLinkRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> HostRead:
    host = await _load_host(db, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    assert_can_access(user, host.owner_sub, detail="Host not found")
    await link_host_credential(db, host, user, data.credential_id)
    await db.flush()
    host = await _load_host(db, host.id)
    assert host is not None
    await log_audit_event(
        db,
        request,
        user,
        action="host.credential.link",
        resource_type="host",
        resource_id=host.id,
        resource_name=host.name,
    )
    return _host_to_read(host)


@router.delete("/{host_id}/credentials/{credential_id}", response_model=HostRead)
async def unlink_credential_from_host(
    host_id: int,
    credential_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> HostRead:
    host = await _load_host(db, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    assert_can_access(user, host.owner_sub, detail="Host not found")
    await unlink_host_credential(db, host, user, credential_id)
    await db.flush()
    host = await _load_host(db, host.id)
    assert host is not None
    await log_audit_event(
        db,
        request,
        user,
        action="host.credential.unlink",
        resource_type="host",
        resource_id=host.id,
        resource_name=host.name,
    )
    return _host_to_read(host)


@router.post("/{host_id}/scan-ssh-fingerprint", response_model=HostSshFingerprintScanResponse)
async def scan_host_ssh_fingerprint(
    host_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> HostSshFingerprintScanResponse:
    from secaudit_core.ssh_fingerprint import scan_ssh_host_key

    host = await db.get(Host, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    assert_can_access(user, host.owner_sub, detail="Host not found")

    os_type = (host.os_type or "linux").strip().lower()
    if os_type != "linux":
        raise HTTPException(
            status_code=400,
            detail="SSH fingerprint scan is only available for Linux hosts",
        )

    try:
        fingerprint, known_hosts_entry = await run_blocking(
            scan_ssh_host_key,
            host.hostname.strip(),
            host.port,
            timeout=settings.blocking_io_timeout_seconds,
        )
    except TimeoutError as exc:
        raise HTTPException(status_code=504, detail="SSH fingerprint scan timed out") from exc
    except (RuntimeError, ValueError) as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    host.ssh_host_key_fingerprint = fingerprint
    host.ssh_known_hosts_entry = known_hosts_entry
    await db.flush()

    await log_audit_event(
        db,
        request,
        user,
        action="host.scan_ssh_fingerprint",
        resource_type="host",
        resource_id=host.id,
        resource_name=host.name,
        metadata={"fingerprint": fingerprint},
    )
    return HostSshFingerprintScanResponse(fingerprint=fingerprint, saved=True)


@router.delete("/{host_id}", status_code=204)
async def delete_host(
    host_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> None:
    host = await db.get(Host, host_id)
    if not host:
        raise HTTPException(status_code=404, detail=_HOST_NOT_FOUND)
    assert_can_access(user, host.owner_sub, detail=_HOST_NOT_FOUND)
    try:
        error = await _delete_host_if_allowed(host_id, db, user)
    except IntegrityError as exc:
        raise HTTPException(status_code=409, detail=_HOST_DELETE_FAILED) from exc
    if error:
        raise HTTPException(status_code=409, detail=error)
    await log_audit_event(
        db,
        request,
        user,
        action="host.delete",
        resource_type="host",
        resource_id=host_id,
        resource_name=host.name if host else None,
    )


@router.put("/{host_id}/tags", response_model=HostRead)
async def set_host_tags(
    host_id: int,
    data: HostTagAssignRequest,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> HostRead:
    host = await db.get(Host, host_id)
    if not host:
        raise HTTPException(status_code=404, detail="Host not found")
    assert_can_access(user, host.owner_sub, detail="Host not found")

    names = sorted(set(name.strip() for name in data.tag_names if name.strip()))
    await db.execute(delete(HostTagLink).where(HostTagLink.host_id == host_id))
    for name in names:
        tag_result = await db.execute(select(HostTag).where(HostTag.name == name))
        tag = tag_result.scalar_one_or_none()
        if not tag:
            tag = HostTag(name=name)
            db.add(tag)
            await db.flush()
        db.add(HostTagLink(host_id=host_id, tag_id=tag.id))

    await db.flush()
    result = await db.execute(
        select(Host)
        .options(selectinload(Host.tags).selectinload(HostTagLink.tag))
        .where(Host.id == host_id)
    )
    return _host_to_read(result.scalar_one())
