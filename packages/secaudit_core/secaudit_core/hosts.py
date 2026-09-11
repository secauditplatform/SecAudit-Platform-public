"""Shared host resolution for compliance and remediation jobs."""

from sqlalchemy import distinct, select
from sqlalchemy.orm import Session, joinedload, selectinload

from secaudit_core.models import Host, HostCredentialLink, HostTag, HostTagLink, JobHost, RemediationJobHost


def resolve_job_host_ids(db: Session, job_id: int) -> list[int]:
    """Resolve host IDs for a compliance job from explicit assignments only."""
    explicit = list(
        db.execute(select(JobHost.host_id).where(JobHost.job_id == job_id)).scalars().all()
    )
    return explicit


def resolve_filter_host_ids(
    db: Session,
    dynamic_filter: dict | None,
    *,
    owner_sub: str | None,
    enforce_owner_scope: bool,
) -> list[int]:
    """Resolve a dynamic filter within its persisted job authorization scope.

    Scoped jobs must have an owner and can select only that owner's hosts.
    Privileged jobs are intentionally unscoped and may also select ownerless
    shared hosts.
    """
    if not dynamic_filter:
        return []
    stmt = select(distinct(Host.id)).where(Host.is_ephemeral.is_(False))
    if enforce_owner_scope:
        if owner_sub is None:
            return []
        stmt = stmt.where(Host.owner_sub == owner_sub)
    if dynamic_filter.get("active_only", True):
        stmt = stmt.where(Host.is_active.is_(True))
    search = (dynamic_filter.get("search") or "").strip()
    if search:
        q = f"%{search}%"
        stmt = stmt.where((Host.name.ilike(q)) | (Host.hostname.ilike(q)))
    tags = [t.strip() for t in dynamic_filter.get("tags", []) if str(t).strip()]
    if tags:
        stmt = stmt.join(HostTagLink, HostTagLink.host_id == Host.id).join(HostTag, HostTag.id == HostTagLink.tag_id)
        stmt = stmt.where(HostTag.name.in_(tags))
    os_type = (dynamic_filter.get("os_type") or "").strip()
    if os_type:
        stmt = stmt.where(Host.os_type == os_type)
    return list(db.execute(stmt).scalars().all())


def find_existing_inventory_host(
    db: Session,
    *,
    owner_sub: str | None,
    ip: str,
    hostname: str | None = None,
) -> Host | None:
    """Reuse a durable inventory host for this owner (never another tenant, never ephemeral)."""
    from sqlalchemy import func, or_

    keys = []
    for value in (ip, hostname):
        text = (value or "").strip().lower()
        if text:
            keys.append(text)
    if not keys:
        return None
    identity = or_(func.lower(Host.hostname).in_(keys), func.lower(Host.name).in_(keys))
    if owner_sub is None:
        owner_match = Host.owner_sub.is_(None)
    else:
        owner_match = or_(Host.owner_sub == owner_sub, Host.owner_sub.is_(None))
    candidates = list(
        db.execute(
            select(Host).where(identity, owner_match, Host.is_ephemeral.is_(False)).limit(20)
        ).scalars()
    )
    if not candidates:
        return None
    same_owner = [host for host in candidates if host.owner_sub == owner_sub]
    return same_owner[0] if same_owner else candidates[0]


def resolve_remediation_host_ids(
    db: Session,
    remediation_job_id: int,
    dynamic_filter: dict | None = None,
    *,
    owner_sub: str | None,
    enforce_owner_scope: bool,
) -> list[int]:
    explicit = list(
        db.execute(
            select(RemediationJobHost.host_id).where(
                RemediationJobHost.remediation_job_id == remediation_job_id
            )
        ).scalars().all()
    )
    if explicit:
        return explicit
    return resolve_filter_host_ids(
        db,
        dynamic_filter,
        owner_sub=owner_sub,
        enforce_owner_scope=enforce_owner_scope,
    )


def resolve_job_targets(
    db: Session,
    job_id: int,
    dynamic_filter: dict | None,
    *,
    owner_sub: str | None,
    enforce_owner_scope: bool,
) -> list[int]:
    explicit = resolve_job_host_ids(db, job_id=job_id)
    if explicit:
        return explicit
    return resolve_filter_host_ids(
        db,
        dynamic_filter,
        owner_sub=owner_sub,
        enforce_owner_scope=enforce_owner_scope,
    )


def load_active_hosts(db: Session, host_ids: list[int]) -> list[Host]:
    if not host_ids:
        return []
    query = (
        select(Host)
        .options(
            joinedload(Host.credential),
            selectinload(Host.credential_links).joinedload(HostCredentialLink.credential),
        )
        .where(Host.is_active.is_(True), Host.id.in_(host_ids))
    )
    return list(db.execute(query).scalars().unique().all())
