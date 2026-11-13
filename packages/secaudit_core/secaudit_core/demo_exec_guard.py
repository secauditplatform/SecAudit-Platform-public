"""Hard target allowlist for remote execution on public demo stands."""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable, Sequence


class DemoExecTargetError(ValueError):
    """Raised when a demo-mode execution target is outside allowed local networks."""


def parse_demo_exec_allowed_cidrs(raw: str | None) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for part in (raw or "").split(","):
        text = part.strip()
        if not text:
            continue
        networks.append(ipaddress.ip_network(text, strict=False))
    return networks


def _connection_host(hostname: str) -> str:
    text = (hostname or "").strip()
    if not text:
        raise DemoExecTargetError("Demo stand: empty execution target")
    if text.startswith("[") and "]" in text:
        return text[1 : text.index("]")]
    if text.count(":") == 1:
        host, maybe_port = text.rsplit(":", 1)
        if maybe_port.isdigit():
            return host
    return text


def resolve_target_ips(hostname: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    host = _connection_host(hostname)
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        return [literal]

    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise DemoExecTargetError(
            f"Demo stand: cannot resolve execution target '{host}'"
        ) from exc

    addresses: list[ipaddress.IPv4Address | ipaddress.IPv6Address] = []
    seen: set[str] = set()
    for info in infos:
        raw = info[4][0]
        if raw in seen:
            continue
        seen.add(raw)
        addresses.append(ipaddress.ip_address(raw))
    if not addresses:
        raise DemoExecTargetError(f"Demo stand: cannot resolve execution target '{host}'")
    return addresses


def assert_target_in_demo_cidrs(
    hostname: str,
    allowed_cidrs: Sequence[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> None:
    if not allowed_cidrs:
        raise DemoExecTargetError(
            "Demo stand: execution allowlist is empty; set DEMO_EXEC_ALLOWED_CIDRS"
        )
    for ip in resolve_target_ips(hostname):
        if not any(ip in network for network in allowed_cidrs):
            raise DemoExecTargetError(
                f"Demo stand: target '{hostname}' resolves to {ip}, "
                "which is outside allowed local networks"
            )


def assert_hostnames_in_demo_cidrs(
    hostnames: Iterable[str],
    *,
    allowed_cidrs_raw: str | None,
) -> None:
    networks = parse_demo_exec_allowed_cidrs(allowed_cidrs_raw)
    for hostname in hostnames:
        assert_target_in_demo_cidrs(hostname, networks)
