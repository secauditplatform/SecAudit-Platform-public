"""Copy AuditFlow discoveries into persistent inventory hosts."""

from __future__ import annotations

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from secaudit_core.inventory_scan import host_name_for_ip, infer_host_defaults
from secaudit_core.models import AuditFlowHost, AuditFlowRun, Host
from secaudit_core.ssh_fingerprint import normalize_ssh_fingerprint


def _ports(row: AuditFlowHost) -> list[int]:
    if not row.open_ports:
        return []
    return [int(p) for p in str(row.open_ports).split(",") if p.strip().isdigit()]


def inventory_port_and_os(row: AuditFlowHost) -> tuple[int, str]:
    ports = _ports(row)
    platform = (row.platform or "").strip().lower()
    if platform == "windows":
        for candidate in (5985, 5986, 445, 3389):
            if candidate in ports:
                return candidate, "windows"
        return 5985, "windows"
    if platform == "network":
        return (22 if 22 in ports else (ports[0] if ports else 22)), "network"
    if 22 in ports:
        return 22, platform or "linux"
    if ports:
        port, inferred = infer_host_defaults(ports)
        return port, platform or inferred
    return 22, platform or "linux"


def _identity_keys(ip: str, hostname: str | None) -> list[str]:
    keys: list[str] = []
    for raw in (ip, hostname):
        if not raw:
            continue
        value = raw.strip().lower()
        if value and value not in keys:
            keys.append(value)
    return keys


def _fingerprint_variants(value: str | None) -> list[str]:
    raw = (value or "").strip()
    if not raw:
        return []
    variants = [raw]
    try:
        normalized = normalize_ssh_fingerprint(raw)
    except ValueError:
        return variants
    if normalized not in variants:
        variants.append(normalized)
    # OpenSSH may store padding; keep both forms for DB match.
    if normalized.startswith("SHA256:"):
        body = normalized.split(":", 1)[1]
        padded = f"SHA256:{body}="
        if padded not in variants:
            variants.append(padded)
    return variants


def _pick_owner_preferred(candidates: list[Host], owner_sub: str | None) -> Host | None:
    if not candidates:
        return None
    same_owner = [host for host in candidates if host.owner_sub == owner_sub]
    return same_owner[0] if same_owner else candidates[0]


def _owner_match(owner_sub: str | None):
    if owner_sub is None:
        return Host.owner_sub.is_(None)
    return or_(Host.owner_sub == owner_sub, Host.owner_sub.is_(None))


def find_inventory_host(
    db: Session,
    *,
    owner_sub: str | None,
    ip: str,
    hostname: str | None,
    ssh_host_key_fingerprint: str | None = None,
) -> Host | None:
    owner_clause = _owner_match(owner_sub)

    fingerprints = _fingerprint_variants(ssh_host_key_fingerprint)
    if fingerprints:
        by_fp = list(
            db.execute(
                select(Host)
                .where(
                    Host.ssh_host_key_fingerprint.in_(fingerprints),
                    owner_clause,
                    Host.is_ephemeral.is_(False),
                )
                .limit(20)
            ).scalars()
        )
        found = _pick_owner_preferred(by_fp, owner_sub)
        if found:
            return found

    keys = _identity_keys(ip, hostname)
    if not keys:
        return None
    identity = or_(func.lower(Host.hostname).in_(keys), func.lower(Host.name).in_(keys))
    candidates = list(
        db.execute(
            select(Host).where(identity, owner_clause, Host.is_ephemeral.is_(False)).limit(20)
        ).scalars()
    )
    return _pick_owner_preferred(candidates, owner_sub)


def persist_audit_flow_hosts_to_inventory(db: Session, run: AuditFlowRun) -> int:
    """Create or reuse inventory hosts for an AuditFlow scan. Returns hosts written.

    AuditFlow secrets stay on the run and are never copied into the credential catalog.
    """
    if not getattr(run, "save_to_inventory", False):
        return 0

    saved = 0
    hosts = list(
        db.execute(select(AuditFlowHost).where(AuditFlowHost.run_id == run.id)).scalars()
    )
    for row in hosts:
        port, os_type = inventory_port_and_os(row)
        existing = find_inventory_host(
            db,
            owner_sub=run.owner_sub,
            ip=row.ip_address,
            hostname=row.hostname,
            ssh_host_key_fingerprint=row.ssh_host_key_fingerprint,
        )
        if existing:
            if existing.owner_sub is None and run.owner_sub:
                existing.owner_sub = run.owner_sub
            if os_type and not existing.os_type:
                existing.os_type = os_type
            if not existing.port:
                existing.port = port
            if row.ssh_known_hosts_entry and not existing.ssh_known_hosts_entry:
                existing.ssh_known_hosts_entry = row.ssh_known_hosts_entry
                existing.ssh_host_key_fingerprint = row.ssh_host_key_fingerprint
            row.ephemeral_host_id = existing.id
            saved += 1
            continue
        host = Host(
            name=host_name_for_ip(row.ip_address, row.hostname),
            hostname=row.ip_address,
            port=port,
            os_type=os_type,
            credential_id=None,
            is_active=True,
            is_ephemeral=False,
            owner_sub=run.owner_sub,
            ssh_host_key_fingerprint=row.ssh_host_key_fingerprint,
            ssh_known_hosts_entry=row.ssh_known_hosts_entry,
        )
        db.add(host)
        db.flush()
        row.ephemeral_host_id = host.id
        saved += 1
    return saved
