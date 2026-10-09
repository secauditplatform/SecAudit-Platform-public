"""Outbound URL safety helpers (SSRF controls for webhooks/SIEM)."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

# Cloud metadata / link-local / loopback that must never be webhook targets.
_BLOCKED_NETWORKS = (
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


class UnsafeOutboundURLError(ValueError):
    """Raised when an outbound URL fails SSRF policy checks."""


def _ip_is_blocked(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    *,
    allow_private: bool,
) -> bool:
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return True
    if isinstance(ip, ipaddress.IPv4Address) and ip.is_reserved:
        return True
    for net in _BLOCKED_NETWORKS:
        if ip in net:
            return True
    if not allow_private and (
        ip.is_private
        or (isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped and ip.ipv4_mapped.is_private)
    ):
        return True
    return False


def validate_outbound_webhook_url(
    url: str,
    *,
    allow_http: bool = False,
    allow_private: bool = False,
) -> str:
    """Validate an operator-supplied webhook/SIEM URL against SSRF policy.

    Requires https (or http when ``allow_http``), rejects userinfo, and resolves
    the hostname to ensure no address is loopback/link-local/metadata.
    Private RFC1918 targets are rejected unless ``allow_private`` is set.
    """
    cleaned = (url or "").strip()
    if not cleaned or len(cleaned) > 2048:
        raise UnsafeOutboundURLError("Outbound URL must be 1–2048 characters")

    parsed = urlparse(cleaned)
    scheme = (parsed.scheme or "").lower()
    if scheme == "https":
        pass
    elif scheme == "http" and allow_http:
        pass
    else:
        raise UnsafeOutboundURLError("Outbound URL must use https")

    if parsed.username is not None or parsed.password is not None:
        raise UnsafeOutboundURLError("Outbound URL must not contain embedded credentials")

    host = parsed.hostname
    if not host:
        raise UnsafeOutboundURLError("Outbound URL host is required")

    if host.lower() in {"localhost", "metadata.google.internal"}:
        raise UnsafeOutboundURLError(f"Outbound URL host is not allowed: {host}")

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        if _ip_is_blocked(literal, allow_private=allow_private):
            raise UnsafeOutboundURLError(f"Outbound URL resolves to a blocked address: {host}")
        return cleaned

    try:
        addrinfo = socket.getaddrinfo(
            host, parsed.port or (443 if scheme == "https" else 80), type=socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise UnsafeOutboundURLError(f"Outbound URL host could not be resolved: {host}") from exc

    if not addrinfo:
        raise UnsafeOutboundURLError(f"Outbound URL host could not be resolved: {host}")

    for info in addrinfo:
        try:
            ip = ipaddress.ip_address(info[4][0])
        except (ValueError, IndexError, TypeError):
            continue
        if _ip_is_blocked(ip, allow_private=allow_private):
            raise UnsafeOutboundURLError(
                f"Outbound URL host resolves to a blocked address ({ip})"
            )
    return cleaned
