"""Outbound URL / header guards to reduce SSRF from webhooks, SIEM, and S3 endpoints."""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

# Cloud metadata and other well-known SSRF targets (hostname form).
_BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "metadata.google.internal",
        "metadata.google",
        "kubernetes.default",
        "kubernetes.default.svc",
    }
)

# Headers operators may attach to outbound webhook/SIEM requests.
_ALLOWED_OUTBOUND_HEADER_NAMES = frozenset(
    {
        "authorization",
        "content-type",
        "user-agent",
        "accept",
        "x-api-key",
        "x-request-id",
        "idempotency-key",
        "x-correlation-id",
    }
)


def _hostname_blocked(hostname: str) -> bool:
    host = hostname.strip().lower().rstrip(".")
    if not host:
        return True
    if host in _BLOCKED_HOSTNAMES:
        return True
    if host.endswith(".localhost") or host.endswith(".local"):
        return True
    if host.endswith(".internal"):
        return True
    return False


def _ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if ip.version == 6 and ip.ipv4_mapped is not None:
        return _ip_blocked(ip.ipv4_mapped)
    blocked = (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )
    if ip.version == 6:
        blocked = blocked or bool(getattr(ip, "is_site_local", False))
    return bool(blocked)


def _parse_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass
    # Bracketed IPv6 from urlparse netloc handling
    if host.startswith("[") and host.endswith("]"):
        try:
            return ipaddress.ip_address(host[1:-1])
        except ValueError:
            return None
    return None


def _resolve_host_ips(hostname: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    literal = _parse_ip(hostname)
    if literal is not None:
        return [literal]

    results: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    try:
        for family, _type, _proto, _canon, sockaddr in socket.getaddrinfo(
            hostname, None, type=socket.SOCK_STREAM
        ):
            addr = sockaddr[0]
            try:
                results.append(ipaddress.ip_address(addr))
            except ValueError:
                continue
    except socket.gaierror as exc:
        raise ValueError(f"Outbound URL host could not be resolved: {hostname!r}") from exc
    if not results:
        raise ValueError(f"Outbound URL host could not be resolved: {hostname!r}")
    return results


def validate_egress_url(
    url: str,
    *,
    allow_http: bool = False,
    allow_private: bool = False,
    resolve_dns: bool = True,
) -> str:
    """Return a normalized URL or raise ValueError if unsafe for server-side fetch.

    Default posture for operator-supplied URLs: HTTPS only, no private/link-local/
    loopback/metadata targets (after DNS resolution).
    """
    raw = (url or "").strip()
    if not raw:
        raise ValueError("Outbound URL is empty")
    if any(ch.isspace() for ch in raw):
        raise ValueError("Outbound URL must not contain whitespace")

    parsed = urlparse(raw)
    scheme = (parsed.scheme or "").lower()
    allowed_schemes = {"https"} if not allow_http else {"https", "http"}
    if scheme not in allowed_schemes:
        raise ValueError(
            f"Outbound URL scheme must be {' or '.join(sorted(allowed_schemes))} (got {scheme!r})"
        )
    if parsed.username or parsed.password:
        raise ValueError("Outbound URL must not embed credentials")
    if not parsed.hostname:
        raise ValueError("Outbound URL host is missing")

    hostname = parsed.hostname
    if _hostname_blocked(hostname):
        raise ValueError(f"Outbound URL host is not allowed: {hostname!r}")

    if not allow_private:
        if resolve_dns:
            for ip in _resolve_host_ips(hostname):
                if _ip_blocked(ip):
                    raise ValueError(
                        f"Outbound URL resolves to a blocked address ({ip}) for host {hostname!r}"
                    )
        else:
            literal = _parse_ip(hostname)
            if literal is not None and _ip_blocked(literal):
                raise ValueError(f"Outbound URL host is a blocked address: {hostname!r}")

    # Rebuild without fragments; keep query/path as provided.
    netloc = parsed.netloc
    normalized = f"{scheme}://{netloc}{parsed.path or ''}"
    if parsed.query:
        normalized = f"{normalized}?{parsed.query}"
    return normalized


def validate_public_https_url(url: str, *, resolve_dns: bool = True) -> str:
    """Strict validation for operator-controlled webhook / SIEM / S3 endpoint URLs."""
    return validate_egress_url(
        url,
        allow_http=False,
        allow_private=False,
        resolve_dns=resolve_dns,
    )


def sanitize_outbound_headers(headers: dict | None) -> dict[str, str]:
    """Keep only allowlisted header names (case-insensitive)."""
    if not headers:
        return {}
    cleaned: dict[str, str] = {}
    for key, value in headers.items():
        name = str(key).strip()
        if not name:
            continue
        if name.lower() not in _ALLOWED_OUTBOUND_HEADER_NAMES:
            continue
        cleaned[name] = str(value)
    return cleaned


_URL_CONFIG_KEYS = ("webhook_url", "url", "endpoint_url")

# Common SMTP submission / lab ports (Mailpit uses 1025).
_ALLOWED_SMTP_PORTS = frozenset({25, 465, 587, 2525, 1025})


def validate_smtp_endpoint(
    host: str,
    port: int | str | None = None,
    *,
    allow_private: bool = False,
    resolve_dns: bool = True,
) -> tuple[str, int]:
    """Validate operator/env SMTP host:port; return normalized (host, port)."""
    hostname = (host or "").strip().lower().rstrip(".")
    if not hostname:
        raise ValueError("SMTP host is empty")
    if any(ch.isspace() for ch in hostname) or "/" in hostname or "\\" in hostname:
        raise ValueError(f"SMTP host is invalid: {host!r}")
    if _hostname_blocked(hostname):
        raise ValueError(f"SMTP host is not allowed: {hostname!r}")

    resolved_port = 587 if port is None or str(port).strip() == "" else int(port)
    if resolved_port not in _ALLOWED_SMTP_PORTS:
        raise ValueError(
            f"SMTP port must be one of {sorted(_ALLOWED_SMTP_PORTS)} (got {resolved_port})"
        )

    if not allow_private:
        if resolve_dns:
            for ip in _resolve_host_ips(hostname):
                if _ip_blocked(ip):
                    raise ValueError(
                        f"SMTP host resolves to a blocked address ({ip}) for host {hostname!r}"
                    )
        else:
            literal = _parse_ip(hostname)
            if literal is not None and _ip_blocked(literal):
                raise ValueError(f"SMTP host is a blocked address: {hostname!r}")

    return hostname, resolved_port


def pinned_https_url(url: str) -> tuple[str, dict[str, str]]:
    """Re-resolve and pin to a validated IP to reduce DNS-rebinding TOCTOU.

    Returns (url_with_ip_literal, extra_headers including Host).
    """
    safe = validate_public_https_url(url, resolve_dns=True)
    parsed = urlparse(safe)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Outbound URL host is missing")
    ips = _resolve_host_ips(hostname)
    for ip in ips:
        if _ip_blocked(ip):
            raise ValueError(
                f"Outbound URL resolves to a blocked address ({ip}) for host {hostname!r}"
            )
    chosen = ips[0]
    host_header = hostname
    if parsed.port:
        host_header = f"{hostname}:{parsed.port}"
    if chosen.version == 6:
        netloc = f"[{chosen}]"
    else:
        netloc = str(chosen)
    if parsed.port:
        netloc = f"{netloc}:{parsed.port}"
    pinned = f"{parsed.scheme}://{netloc}{parsed.path or ''}"
    if parsed.query:
        pinned = f"{pinned}?{parsed.query}"
    return pinned, {"Host": host_header}


def validate_channel_config_egress(
    *,
    channel_type: str | None,
    config_json: dict | None,
    secret: str | None = None,
) -> dict | None:
    """Validate operator-supplied channel URLs/SMTP; return config with sanitized headers."""
    config = dict(config_json) if isinstance(config_json, dict) else None
    urls: list[str] = []
    if secret and str(secret).strip().lower().startswith("http"):
        urls.append(str(secret).strip())
    if config:
        for key in _URL_CONFIG_KEYS:
            value = config.get(key)
            if value:
                urls.append(str(value).strip())
        if isinstance(config.get("headers"), dict):
            config["headers"] = sanitize_outbound_headers(config["headers"])
        smtp_host = config.get("smtp_host")
        if smtp_host:
            host, port = validate_smtp_endpoint(
                str(smtp_host),
                config.get("smtp_port"),
                allow_private=False,
            )
            config["smtp_host"] = host
            config["smtp_port"] = port
    for url in urls:
        validate_public_https_url(url)
    return config
