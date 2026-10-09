"""Import AD/LDAP computers into the host inventory."""

from __future__ import annotations

from sqlalchemy import create_engine, or_, select
from sqlalchemy.orm import Session, sessionmaker

from secaudit_core.directory_discovery import (
    MAX_COMPUTERS,
    DirectoryBind,
    DirectoryDiscoveryError,
    KnownHost,
    plan_directory_import,
    search_computers,
)
from secaudit_core.models import DirectorySource, DirectorySync, Host, InventoryScanResult, JobStatus
from secaudit_core.run_state import claim_pending_run, transition_running_run
from secaudit_core.secrets import decrypt_secret
from secaudit_core.settings import SecAuditSettings


def run_directory_sync(sync_id: int, *, database_url: str, settings: SecAuditSettings) -> None:
    engine = create_engine(database_url)
    session_local = sessionmaker(bind=engine)
    bind: DirectoryBind | None = None
    owner_sub: str | None = None
    map_ou_to_site = True

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
        bind = DirectoryBind(
            server=source.server,
            port=source.port,
            use_ssl=source.use_ssl,
            start_tls=source.start_tls,
            verify_tls=source.verify_tls,
            base_dn=source.base_dn,
            bind_dn=source.bind_dn,
            password=password,
            enabled_only=source.enabled_only,
        )
        owner_sub = sync.owner_sub
        map_ou_to_site = source.map_ou_to_site

    assert bind is not None
    try:
        discovered = search_computers(bind)
    except DirectoryDiscoveryError as exc:
        with session_local() as db:
            _fail(db, sync_id, str(exc))
        return
    except Exception:
        with session_local() as db:
            _fail(db, sync_id, "Directory search failed")
        return

    with session_local() as db:
        sync = db.get(DirectorySync, sync_id)
        if sync is None or sync.status != JobStatus.RUNNING:
            return
        known, aliases = _load_known_hosts(db, owner_sub)
        plan = plan_directory_import(
            discovered.computers,
            known,
            aliases=aliases,
            map_ou_to_site=map_ou_to_site,
        )
        updated_ids = {item.host_id for item in plan.updates}
        claimed = _apply_plan(db, plan, owner_sub=owner_sub)
        extra_updates = [host_id for host_id in claimed if host_id not in updated_ids]
        sync.hosts_found = len(discovered.computers)
        sync.hosts_created = len(plan.creates)
        sync.hosts_updated = len(plan.updates) + len(extra_updates)
        sync.hosts_matched = max(0, len(plan.matched_ids) - len(extra_updates))
        if discovered.truncated:
            sync.error_message = (
                f"Import stopped at {MAX_COMPUTERS} computers. Narrow the base DN to import the rest."
            )
        db.commit()
        transition_running_run(db, DirectorySync, sync_id, JobStatus.COMPLETED)


def _load_known_hosts(db: Session, owner_sub: str | None) -> tuple[list[KnownHost], dict[str, int]]:
    if owner_sub is None:
        owner_match = Host.owner_sub.is_(None)
    else:
        owner_match = or_(Host.owner_sub == owner_sub, Host.owner_sub.is_(None))
    hosts = list(db.execute(select(Host).where(owner_match)).scalars())
    known = [
        KnownHost(
            id=host.id,
            name=host.name,
            hostname=host.hostname,
            os_type=host.os_type,
            site=host.site,
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

    for item in plan.creates:
        db.add(
            HostModel(
                name=item.name,
                hostname=item.hostname,
                port=item.port,
                os_type=item.os_type,
                site=item.site,
                is_active=item.is_active,
                owner_sub=owner_sub,
            )
        )
    touched = {item.host_id: item for item in plan.updates}
    claim_ids = list(touched) + list(plan.matched_ids)
    claimed: list[int] = []
    if not claim_ids:
        return claimed
    rows = list(db.execute(select(HostModel).where(HostModel.id.in_(claim_ids))).scalars())
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
        if host.owner_sub is None and owner_sub is not None:
            host.owner_sub = owner_sub
    for host_id in plan.matched_ids:
        host = by_id.get(host_id)
        if host is None or not _owner_allows(host.owner_sub, owner_sub):
            continue
        if host.owner_sub is None and owner_sub is not None:
            host.owner_sub = owner_sub
            claimed.append(host_id)
    return claimed


def _owner_allows(host_owner: str | None, sync_owner: str | None) -> bool:
    if sync_owner is None:
        return host_owner is None
    return host_owner in (None, sync_owner)


def _fail(db: Session, sync_id: int, message: str) -> None:
    transition_running_run(db, DirectorySync, sync_id, JobStatus.FAILED, error_message=message)
