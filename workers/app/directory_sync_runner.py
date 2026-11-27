"""Import AD/LDAP computers into the host inventory."""

from __future__ import annotations

from sqlalchemy import create_engine, or_, select
from sqlalchemy.orm import Session, sessionmaker

from secaudit_core.directory_discovery import (
    DIRECTORY_MANAGED_TAG,
    DIRECTORY_STALE_TAG,
    DirectoryBind,
    DirectoryDiscoveryError,
    KnownHost,
    clamp_import_limit,
    mapped_attributes,
    normalize_ou_field_map,
    plan_directory_import,
    search_computers,
    validate_computer_filter,
)
from secaudit_core.models import DirectorySource, DirectorySync, Host, HostTag, HostTagLink, InventoryScanResult, JobStatus
from secaudit_core.run_state import claim_pending_run, transition_running_run
from secaudit_core.secrets import decrypt_secret
from secaudit_core.settings import SecAuditSettings


def run_directory_sync(sync_id: int, *, database_url: str, settings: SecAuditSettings) -> None:
    engine = create_engine(database_url)
    session_local = sessionmaker(bind=engine)
    bind: DirectoryBind | None = None
    owner_sub: str | None = None
    map_ou_to_site = True
    missing_host_policy = "none"
    field_map: dict[str, str] = {}
    import_limit = settings.directory_max_computers

    with session_local() as db:
        if not claim_pending_run(db, DirectorySync, sync_id):
            return
        sync = db.get(DirectorySync, sync_id)
        if sync is None:
            return
        source = db.get(DirectorySource, sync.source_id)
        if source is None or not source.is_active:
            _fail(db, sync_id, "Directory source is missing or disabled")
            return
        try:
            password = decrypt_secret(source.encrypted_bind_password, settings)
        except Exception:
            _fail(db, sync_id, "Stored bind password could not be read")
            return
        # Lifecycle needs disabled accounts when policy is active.
        search_enabled_only = source.enabled_only and (source.missing_host_policy or "none") == "none"
        try:
            field_map = normalize_ou_field_map(source.ou_field_map or {})
            search_filter = validate_computer_filter(source.computer_filter)
        except ValueError as exc:
            _fail(db, sync_id, str(exc))
            return
        import_limit = clamp_import_limit(source.import_limit, default=settings.directory_max_computers)
        bind = DirectoryBind(
            server=source.server,
            port=source.port,
            use_ssl=source.use_ssl,
            start_tls=source.start_tls,
            verify_tls=source.verify_tls,
            base_dn=source.base_dn,
            bind_dn=source.bind_dn,
            password=password,
            enabled_only=search_enabled_only,
            search_filter=search_filter,
            extra_attributes=mapped_attributes(field_map),
        )
        owner_sub = sync.owner_sub
        map_ou_to_site = source.map_ou_to_site
        missing_host_policy = source.missing_host_policy or "none"

    assert bind is not None
    try:
        discovered = search_computers(bind, limit=import_limit)
    except DirectoryDiscoveryError as exc:
        with session_local() as db:
            _fail(db, sync_id, str(exc))
        return
    except Exception:
        with session_local() as db:
            _fail(db, sync_id, "Directory search failed")
        return

    computers = discovered.computers

    with session_local() as db:
        sync = db.get(DirectorySync, sync_id)
        if sync is None or sync.status != JobStatus.RUNNING:
            return
        known, aliases = _load_known_hosts(db, owner_sub)
        plan = plan_directory_import(
            computers,
            known,
            aliases=aliases,
            map_ou_to_site=map_ou_to_site,
            missing_host_policy=missing_host_policy,
            ou_field_map=field_map,
        )
        updated_ids = {item.host_id for item in plan.updates}
        claimed = _apply_plan(db, plan, owner_sub=owner_sub)
        extra_updates = [host_id for host_id in claimed if host_id not in updated_ids]
        sync.hosts_found = len(computers)
        sync.hosts_created = len(plan.creates)
        sync.hosts_updated = len(plan.updates) + len(extra_updates) + len(plan.lifecycle)
        sync.hosts_matched = max(0, len(plan.matched_ids) - len(extra_updates))
        if discovered.truncated:
            sync.error_message = (
                f"Import stopped at {import_limit} computers. Narrow the base DN or raise the computer limit."
            )
        db.commit()
        transition_running_run(db, DirectorySync, sync_id, JobStatus.COMPLETED)


def _load_known_hosts(db: Session, owner_sub: str | None) -> tuple[list[KnownHost], dict[str, int]]:
    if owner_sub is None:
        owner_match = Host.owner_sub.is_(None)
    else:
        owner_match = or_(Host.owner_sub == owner_sub, Host.owner_sub.is_(None))
    hosts = list(db.execute(select(Host).where(owner_match)).scalars())
    host_ids = [host.id for host in hosts]
    managed_ids: set[int] = set()
    if host_ids:
        tag = db.execute(select(HostTag).where(HostTag.name == DIRECTORY_MANAGED_TAG)).scalar_one_or_none()
        if tag is not None:
            links = db.execute(
                select(HostTagLink.host_id).where(
                    HostTagLink.tag_id == tag.id,
                    HostTagLink.host_id.in_(host_ids),
                )
            ).scalars()
            managed_ids = set(links)
    known = [
        KnownHost(
            id=host.id,
            name=host.name,
            hostname=host.hostname,
            os_type=host.os_type,
            site=host.site,
            is_active=bool(host.is_active),
            directory_managed=host.id in managed_ids,
            os_family=host.os_family,
            os_version=host.os_version,
            environment=host.environment,
            criticality=host.criticality,
        )
        for host in hosts
    ]
    visible = {host.id for host in hosts}
    aliases: dict[str, int] = {}
    rows = db.execute(
        select(InventoryScanResult.resolved_hostname, InventoryScanResult.host_id).where(
            InventoryScanResult.host_id.is_not(None),
            InventoryScanResult.resolved_hostname.is_not(None),
        )
    )
    for resolved, host_id in rows:
        if host_id in visible and resolved:
            aliases.setdefault(str(resolved).strip().lower(), host_id)
    return known, aliases


def _apply_plan(db: Session, plan, *, owner_sub: str | None) -> list[int]:
    """Create and update hosts. Returns ids whose empty owner was claimed."""
    from secaudit_core.models import Host as HostModel

    created_hosts: list[HostModel] = []
    for item in plan.creates:
        host = HostModel(
            name=item.name,
            hostname=item.hostname,
            port=item.port,
            os_type=item.os_type,
            os_family=item.os_family,
            os_version=item.os_version,
            site=item.site,
            environment=item.environment,
            criticality=item.criticality,
            is_active=item.is_active,
            owner_sub=owner_sub,
        )
        db.add(host)
        created_hosts.append(host)
    db.flush()
    for host in created_hosts:
        _ensure_host_tag(db, host.id, DIRECTORY_MANAGED_TAG)

    touched = {item.host_id: item for item in plan.updates}
    claim_ids = list(touched) + list(plan.matched_ids) + [item.host_id for item in plan.lifecycle]
    claimed: list[int] = []
    if not claim_ids and not created_hosts:
        return claimed
    rows = list(db.execute(select(HostModel).where(HostModel.id.in_(claim_ids))).scalars()) if claim_ids else []
    by_id = {host.id: host for host in rows}
    for host_id, item in touched.items():
        host = by_id.get(host_id)
        if host is None or not _owner_allows(host.owner_sub, owner_sub):
            continue
        if item.name is not None:
            host.name = item.name
        if item.os_type is not None:
            host.os_type = item.os_type
        if item.site is not None:
            host.site = item.site
        if item.os_family is not None and not (host.os_family or "").strip():
            host.os_family = item.os_family
        if item.os_version is not None and not (host.os_version or "").strip():
            host.os_version = item.os_version
        if item.environment is not None and not (host.environment or "").strip():
            host.environment = item.environment
        if item.criticality is not None and not (host.criticality or "").strip():
            host.criticality = item.criticality
        if item.is_active is not None:
            host.is_active = item.is_active
        if host.owner_sub is None and owner_sub is not None:
            host.owner_sub = owner_sub
        _ensure_host_tag(db, host.id, DIRECTORY_MANAGED_TAG)
    for host_id in plan.matched_ids:
        host = by_id.get(host_id)
        if host is None or not _owner_allows(host.owner_sub, owner_sub):
            continue
        if host.owner_sub is None and owner_sub is not None:
            host.owner_sub = owner_sub
            claimed.append(host_id)
        _ensure_host_tag(db, host.id, DIRECTORY_MANAGED_TAG)
    for item in plan.lifecycle:
        host = by_id.get(item.host_id)
        if host is None or not _owner_allows(host.owner_sub, owner_sub):
            continue
        if item.set_inactive:
            host.is_active = False
        if item.tag_stale:
            _ensure_host_tag(db, host.id, DIRECTORY_STALE_TAG)
    return claimed


def _ensure_host_tag(db: Session, host_id: int, tag_name: str) -> None:
    tag = db.execute(select(HostTag).where(HostTag.name == tag_name)).scalar_one_or_none()
    if tag is None:
        tag = HostTag(name=tag_name)
        db.add(tag)
        db.flush()
    existing = db.execute(
        select(HostTagLink).where(HostTagLink.host_id == host_id, HostTagLink.tag_id == tag.id)
    ).scalar_one_or_none()
    if existing is None:
        db.add(HostTagLink(host_id=host_id, tag_id=tag.id))


def _owner_allows(host_owner: str | None, sync_owner: str | None) -> bool:
    if sync_owner is None:
        return host_owner is None
    return host_owner in (None, sync_owner)


def _fail(db: Session, sync_id: int, message: str) -> None:
    transition_running_run(db, DirectorySync, sync_id, JobStatus.FAILED, error_message=message)
