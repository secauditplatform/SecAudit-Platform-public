"""Resolve an AuditFlow template inventory rule into scan targets.

The template stores the tag and site. A run reads the hosts that match at
that moment and merges them with any CIDR or address already written on the
template. Discovery still decides which of those targets are up.
"""

from __future__ import annotations

import ipaddress
import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from secaudit_core.inventory_scan import MIN_CIDR_PREFIX_LEN_ABSOLUTE, validate_scan_target
from secaudit_core.models import Host, HostTag, HostTagLink
from secaudit_core.ssh_fingerprint import normalize_ssh_fingerprint

MAX_AUDIT_FLOW_TARGETS = 16
_SPLIT = re.compile(r"[\s,;\r\n]+")


def normalize_inventory_scope(raw: dict | None) -> dict | None:
    """Return ``{"tags": [...], "site": str | None}`` or None when the rule is empty."""
    if not raw:
        return None
    tags: list[str] = []
    seen: set[str] = set()
    for item in raw.get("tags") or []:
        tag = str(item).strip()[:64]
        if not tag or tag.lower() in seen:
            continue
        seen.add(tag.lower())
        tags.append(tag)
    site = str(raw.get("site") or "").strip()[:64] or None
    if not tags and not site:
        return None
    return {"tags": tags, "site": site}


def inventory_scope_host_stmt(scope: dict, *, owner_sub: str | None):
    """Hosts this owner currently has under the saved tag and site.

    A missing owner matches nothing, so a template cannot scan another tenant.
    """
    normalized = normalize_inventory_scope(scope)
    if normalized is None or not owner_sub:
        return None
    stmt = select(Host.hostname, Host.name, Host.ssh_host_key_fingerprint).where(
        Host.is_ephemeral.is_(False),
        Host.is_active.is_(True),
        Host.owner_sub == owner_sub,
    )
    if normalized["tags"]:
        stmt = (
            stmt.join(HostTagLink, HostTagLink.host_id == Host.id)
            .join(HostTag, HostTag.id == HostTagLink.tag_id)
            .where(HostTag.name.in_(normalized["tags"]))
        )
    if normalized["site"]:
        stmt = stmt.where(Host.site == normalized["site"])
    return stmt.distinct()


def load_inventory_scope_hosts(db: Session, scope: dict, *, owner_sub: str | None) -> list[dict]:
    stmt = inventory_scope_host_stmt(scope, owner_sub=owner_sub)
    if stmt is None:
        return []
    return host_rows_to_targets(db.execute(stmt).all())


def host_rows_to_targets(rows) -> list[dict]:
    hosts: list[dict] = []
    for row in rows:
        hosts.append(
            {
                "hostname": row[0] or "",
                "name": row[1] or "",
                "ssh_host_key_fingerprint": row[2],
            }
        )
    return hosts


def compose_template_targets(
    explicit: list[str],
    hosts: list[dict],
    *,
    scope_active: bool,
) -> list[str]:
    """Targets for one run. Without a scope, the saved list is used as stored."""
    if not scope_active:
        return [part for item in explicit or [] for part in _tokens(item)]
    merged = merge_inventory_scope_targets(explicit, hosts)
    if not merged:
        raise ValueError("Inventory scope matched no hosts")
    limit = MIN_CIDR_PREFIX_LEN_ABSOLUTE
    return [validate_scan_target(item, max_prefix_len=limit) for item in merged]


def merge_inventory_scope_targets(explicit: list[str], hosts: list[dict]) -> list[str]:
    """Keep written targets, then add inventory hosts that are not already covered.

    An address inside a written CIDR is not added again. A second inventory host
    with the same SSH fingerprint is not added either, including when the first
    copy is already inside that CIDR.
    """
    tokens = [part for item in explicit or [] for part in _tokens(item)]
    seen_tokens = {_address_key(token) for token in tokens}
    seen_fp: set[str] = set()
    for host in hosts or []:
        target = _target_of(host)
        if not target or not _covered(target, tokens):
            continue
        fingerprint = _fingerprint_key(host.get("ssh_host_key_fingerprint"))
        if fingerprint:
            seen_fp.add(fingerprint)

    for host in hosts or []:
        target = _target_of(host)
        if not target:
            continue
        if _address_key(target) in seen_tokens or _covered(target, tokens):
            continue
        fingerprint = _fingerprint_key(host.get("ssh_host_key_fingerprint"))
        if fingerprint and fingerprint in seen_fp:
            continue
        if len(tokens) >= MAX_AUDIT_FLOW_TARGETS:
            raise ValueError("At most 16 scan targets are allowed")
        tokens.append(target)
        seen_tokens.add(_address_key(target))
        if fingerprint:
            seen_fp.add(fingerprint)
    return tokens


def _tokens(item: str) -> list[str]:
    return [part.strip() for part in _SPLIT.split(str(item).strip()) if part.strip()]


def _address_key(value: str) -> str:
    return value.strip().lower()


def _target_of(host: dict) -> str | None:
    hostname = str(host.get("hostname") or "").strip()
    if hostname:
        return hostname
    name = str(host.get("name") or "").strip()
    return name or None


def _fingerprint_key(value: str | None) -> str | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        return normalize_ssh_fingerprint(text)
    except ValueError:
        return None


def _covered(address: str, tokens: list[str]) -> bool:
    key = _address_key(address)
    if key in {_address_key(token) for token in tokens}:
        return True
    try:
        ip = ipaddress.ip_address(address.strip())
    except ValueError:
        return False
    for token in tokens:
        if "/" not in token:
            continue
        try:
            net = ipaddress.ip_network(token.strip(), strict=False)
        except ValueError:
            continue
        if ip.version == net.version and ip in net:
            return True
    return False
