"""Stable asset identities for host merge across IP / DNS changes."""

from __future__ import annotations

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from secaudit_core.enums import AssetIdentityKind
from secaudit_core.models import AssetIdentity, Host

_KIND_ALIASES: dict[str, AssetIdentityKind] = {
    "ssh_fingerprint": AssetIdentityKind.SSH_FINGERPRINT,
    "ssh": AssetIdentityKind.SSH_FINGERPRINT,
    "winrm_thumbprint": AssetIdentityKind.WINRM_THUMBPRINT,
    "winrm": AssetIdentityKind.WINRM_THUMBPRINT,
    "snmp_serial": AssetIdentityKind.SNMP_SERIAL,
    "serial": AssetIdentityKind.SNMP_SERIAL,
    "machine_id": AssetIdentityKind.MACHINE_ID,
    "machineguid": AssetIdentityKind.MACHINE_ID,
    "mac": AssetIdentityKind.MAC,
}


def normalize_identity_kind(kind: AssetIdentityKind | str) -> AssetIdentityKind:
    if isinstance(kind, AssetIdentityKind):
        return kind
    key = str(kind or "").strip().lower().replace("-", "_")
    mapped = _KIND_ALIASES.get(key)
    if mapped is None:
        raise ValueError(f"Unsupported asset identity kind: {kind}")
    return mapped


def normalize_identity_value(kind: AssetIdentityKind | str, value: str) -> str:
    kind_enum = normalize_identity_kind(kind)
    text = str(value or "").strip()
    if not text:
        raise ValueError("Asset identity value is empty")
    if kind_enum == AssetIdentityKind.MAC:
        cleaned = text.lower().replace("-", ":").replace(".", ":")
        parts = [part for part in cleaned.split(":") if part]
        if len(parts) == 6 and all(len(part) <= 2 for part in parts):
            return ":".join(part.zfill(2) for part in parts)
        return cleaned
    return text.lower()


def upsert_asset_identity(
    db: Session,
    *,
    host_id: int,
    kind: AssetIdentityKind | str,
    value: str,
) -> AssetIdentity:
    kind_enum = normalize_identity_kind(kind)
    normalized = normalize_identity_value(kind_enum, value)
    existing = db.execute(
        select(AssetIdentity).where(
            AssetIdentity.kind == kind_enum,
            AssetIdentity.value == normalized,
        )
    ).scalar_one_or_none()
    if existing is not None:
        if existing.host_id != host_id:
            existing.host_id = host_id
        return existing
    row = AssetIdentity(host_id=host_id, kind=kind_enum, value=normalized)
    db.add(row)
    db.flush()
    return row


def find_host_by_identities(
    db: Session,
    *,
    owner_sub: str | None,
    identities: dict[AssetIdentityKind | str, str | None] | None = None,
    ssh_fingerprint: str | None = None,
) -> Host | None:
    """Return the best matching non-ephemeral host for any provided identity."""
    pairs: list[tuple[AssetIdentityKind, str]] = []
    for kind, raw in (identities or {}).items():
        if raw is None or not str(raw).strip():
            continue
        kind_enum = normalize_identity_kind(kind)
        pairs.append((kind_enum, normalize_identity_value(kind_enum, str(raw))))
    if ssh_fingerprint and str(ssh_fingerprint).strip():
        pairs.append(
            (
                AssetIdentityKind.SSH_FINGERPRINT,
                normalize_identity_value(AssetIdentityKind.SSH_FINGERPRINT, ssh_fingerprint),
            )
        )
    if not pairs:
        return None

    if owner_sub is None:
        owner_match = Host.owner_sub.is_(None)
    else:
        owner_match = or_(Host.owner_sub == owner_sub, Host.owner_sub.is_(None))

    clauses = [
        (AssetIdentity.kind == kind) & (AssetIdentity.value == value) for kind, value in pairs
    ]
    rows = list(
        db.execute(
            select(Host, AssetIdentity)
            .join(AssetIdentity, AssetIdentity.host_id == Host.id)
            .where(or_(*clauses), owner_match, Host.is_ephemeral.is_(False))
            .limit(40)
        ).all()
    )
    if not rows:
        # Legacy column still used before backfill / for hosts without rows.
        fps = [value for kind, value in pairs if kind == AssetIdentityKind.SSH_FINGERPRINT]
        if fps:
            legacy = list(
                db.execute(
                    select(Host)
                    .where(
                        Host.ssh_host_key_fingerprint.in_(fps),
                        owner_match,
                        Host.is_ephemeral.is_(False),
                    )
                    .limit(20)
                )
                .scalars()
                .all()
            )
            if legacy:
                same_owner = [host for host in legacy if host.owner_sub == owner_sub]
                return same_owner[0] if same_owner else legacy[0]
        return None

    hosts = [host for host, _ in rows]
    same_owner = [host for host in hosts if host.owner_sub == owner_sub]
    return same_owner[0] if same_owner else hosts[0]


def retarget_host_address(host: Host, new_address: str | None) -> bool:
    """Update ``Host.hostname`` when identity matched under a new IP/DNS."""
    address = str(new_address or "").strip()
    if not address or host.hostname == address:
        return False
    host.hostname = address[:256]
    return True
