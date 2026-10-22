"""Resolve the audit/client IP without trusting spoofable forwarded headers."""

from __future__ import annotations

import ipaddress
import logging
from functools import lru_cache

from fastapi import Request

from app.core.config import settings

logger = logging.getLogger(__name__)


def _parse_ip(value: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not value:
        return None
    text = value.strip().strip('"')
    if not text:
        return None
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        return None
    if isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped:
        return parsed.ipv4_mapped
    return parsed


@lru_cache(maxsize=8)
def _trusted_networks(
    raw: str,
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    networks = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        try:
            networks.append(ipaddress.ip_network(token, strict=False))
        except ValueError:
            logger.warning("Ignoring invalid TRUSTED_PROXIES entry: %s", token)
    return tuple(networks)


def _is_trusted(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(ip in network for network in _trusted_networks(settings.trusted_proxies or ""))


def client_ip(request: Request) -> str:
    """Return XFF only when the direct peer is an explicitly trusted proxy.

    With no TRUSTED_PROXIES configured, forwarded headers are ignored entirely:
    a client cannot rotate its rate-limit key by sending X-Forwarded-For.
    """
    peer_raw = request.client.host if request.client and request.client.host else "unknown"
    peer = _parse_ip(peer_raw)
    if peer is None or not _is_trusted(peer):
        return peer_raw

    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        candidates = [_parse_ip(part) for part in forwarded.split(",")]
        valid = [ip for ip in candidates if ip is not None]
        for candidate in reversed(valid):
            if not _is_trusted(candidate):
                return str(candidate)
        if valid:
            return str(valid[0])

    real_ip = _parse_ip(request.headers.get("x-real-ip"))
    if real_ip is not None:
        return str(real_ip)
    return peer_raw
