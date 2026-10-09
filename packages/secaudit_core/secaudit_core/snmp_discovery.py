"""Plan an SNMP inventory probe.

The probe reads sysDescr, sysObjectID and sysName only. It does not walk
vendor MIBs, send SET, or listen for traps. Address limits match the nmap
inventory scan: the API validates the prefix, and this module expands it.
"""

from __future__ import annotations

import ipaddress
import socket

from secaudit_core.inventory_scan import expand_scan_target, validate_scan_target
from secaudit_core.sensitive_data import redact_sensitive

SYS_DESCR_OID = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID_OID = "1.3.6.1.2.1.1.2.0"
SYS_NAME_OID = "1.3.6.1.2.1.1.5.0"
SNMP_OIDS = (SYS_DESCR_OID, SYS_OBJECT_ID_OID, SYS_NAME_OID)

DEFAULT_SNMP_PORT = 161
MAX_SNMP_ADDRESSES = 65536
_HINT_LIMIT = 512

AUTH_PROTOCOLS = frozenset({"MD5", "SHA", "SHA224", "SHA256", "SHA384", "SHA512"})
PRIV_PROTOCOLS = frozenset({"DES", "AES", "AES192", "AES256"})


class SnmpDiscoveryError(ValueError):
    """The SNMP target cannot be probed."""


def normalize_auth_protocol(value: str | None) -> str:
    token = (value or "SHA256").strip().upper()
    if token not in AUTH_PROTOCOLS:
        raise SnmpDiscoveryError(f"Unsupported SNMP auth protocol: {token}")
    return token


def normalize_priv_protocol(value: str | None) -> str | None:
    if value is None or not str(value).strip():
        return None
    token = str(value).strip().upper()
    if token not in PRIV_PROTOCOLS:
        raise SnmpDiscoveryError(f"Unsupported SNMP privacy protocol: {token}")
    return token


def snmp_addresses(target: str, *, max_prefix_len: int | None = None) -> list[str]:
    """Expand a validated inventory target into probe addresses.

    IPv4 CIDR uses the same prefix ceiling as nmap. An IPv6 prefix is rejected:
    a /64 is not a /24. A hostname is resolved and each address is checked
    against the same block list as a literal IP.
    """
    cleaned = validate_scan_target(target, max_prefix_len=max_prefix_len)
    if "/" in cleaned:
        try:
            net = ipaddress.ip_network(cleaned, strict=False)
        except ValueError as exc:
            raise SnmpDiscoveryError("Invalid CIDR notation") from exc
        if isinstance(net, ipaddress.IPv6Network):
            raise SnmpDiscoveryError(
                "IPv6 prefixes are not expanded for SNMP; probe one address"
            )
    expanded = expand_scan_target(cleaned)
    if expanded is None:
        if "/" in cleaned:
            raise SnmpDiscoveryError("SNMP scan accepts an IP, a hostname, or an IPv4 CIDR")
        expanded = _resolve_hostname(cleaned, max_prefix_len=max_prefix_len)
    if len(expanded) > MAX_SNMP_ADDRESSES:
        raise SnmpDiscoveryError("SNMP target expands past the inventory scan limit")
    return expanded


def _resolve_hostname(hostname: str, *, max_prefix_len: int | None) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_DGRAM)
    except socket.gaierror as exc:
        raise SnmpDiscoveryError(f"Could not resolve SNMP target: {hostname}") from exc
    addresses: list[str] = []
    for info in infos:
        raw = info[4][0]
        try:
            addresses.append(str(ipaddress.ip_address(raw.split("%", 1)[0])))
        except ValueError:
            continue
    if not addresses:
        raise SnmpDiscoveryError(f"Could not resolve SNMP target: {hostname}")
    unique: list[str] = []
    for address in addresses:
        if address not in unique:
            unique.append(address)
    allowed: list[str] = []
    for address in unique:
        try:
            allowed.append(validate_scan_target(address, max_prefix_len=max_prefix_len))
        except ValueError:
            continue
    if not allowed:
        raise SnmpDiscoveryError("Resolved addresses are not allowed")
    return allowed


def platform_hint(sys_descr: str | None, sys_object_id: str | None) -> str | None:
    """Text the profile matcher can read the same way it reads an nmap OS line."""
    lines: list[str] = []
    descr = _clean_fact(sys_descr)
    object_id = _clean_fact(sys_object_id)
    if descr:
        lines.append(descr)
    if object_id:
        lines.append(object_id)
    if not lines:
        return None
    return "\n".join(lines)[:_HINT_LIMIT]


def safe_snmp_error(message: str, *secrets: str) -> str:
    """Drop community strings and v3 keys before the text is stored or shown."""
    text = message or "SNMP discovery failed"
    redacted = redact_sensitive(text)
    if not isinstance(redacted, str):
        redacted = str(redacted)
    for secret in secrets:
        if secret and secret in redacted:
            redacted = redacted.replace(secret, "[REDACTED]")
    redacted = redacted.strip()
    return (redacted or "SNMP discovery failed")[:500]


def _clean_fact(value: str | None) -> str | None:
    if not value:
        return None
    text = redact_sensitive(value)
    if not isinstance(text, str):
        text = str(text)
    cleaned = " ".join(text.split())
    return cleaned or None
