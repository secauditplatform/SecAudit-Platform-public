"""Pre-flight helpers: TCP reachability and profile↔host platform matching."""

from __future__ import annotations

import ipaddress
import re
import socket
import time
from typing import Literal

CheckStatus = Literal["ok", "fail", "skip"]


def tcp_reachable(
    host: str,
    port: int,
    *,
    timeout: float = 5.0,
    attempts: int = 1,
) -> tuple[bool, str]:
    """Return (ok, detail) for a TCP connect to host:port.

    Hostnames try IPv4 before IPv6 so a black-holed AAAA does not burn the
    whole budget before a working A record is tried. ``attempts`` covers
    transient Docker/VPN drops to remote SSH endpoints.
    """
    target = (host or "").strip()
    if not target:
        return False, "empty_host"
    try:
        port_n = int(port)
    except (TypeError, ValueError):
        return False, "invalid_port"
    if port_n < 1 or port_n > 65535:
        return False, "invalid_port"

    tries = max(1, int(attempts))
    last_detail = "unreachable"
    for attempt in range(tries):
        try:
            _tcp_connect(target, port_n, timeout=timeout)
            return True, f"{target}:{port_n}"
        except OSError as exc:
            last_detail = str(exc) or "unreachable"
            if attempt + 1 < tries:
                time.sleep(min(0.5, max(0.1, timeout / 10)))
    return False, last_detail


def _tcp_connect(host: str, port: int, *, timeout: float) -> None:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        if not infos:
            raise OSError("name resolution failed")
        # Prefer IPv4: broken IPv6 routes are common on Docker Desktop / VPN.
        infos = sorted(infos, key=lambda info: 0 if info[0] == socket.AF_INET else 1)
        last_exc: OSError | None = None
        for family, socktype, proto, _canon, sockaddr in infos:
            sock: socket.socket | None = None
            try:
                sock = socket.socket(family, socktype, proto)
                sock.settimeout(timeout)
                sock.connect(sockaddr)
                return
            except OSError as exc:
                last_exc = exc
            finally:
                if sock is not None:
                    sock.close()
        raise last_exc or OSError("unreachable")
    with socket.create_connection((host, port), timeout=timeout):
        return


def host_platform(os_type: str | None) -> str:
    value = (os_type or "").strip().lower()
    if value in {"windows", "win"}:
        return "windows"
    if value in {"network", "network device"}:
        return "network"
    if value in {
        "unix",
        "freebsd",
        "openbsd",
        "netbsd",
        "dragonfly",
        "solaris",
        "illumos",
        "aix",
        "hpux",
        "hp-ux",
        "sunos",
        "macos",
        "darwin",
    }:
        return "unix"
    if value:
        return "linux"
    return "unknown"


def profile_platform(*, os_name: str | None, category_name: str | None, category_slug: str | None = None) -> str:
    """Coarse platform bucket for a profile (linux/windows/unix/network)."""
    slug = (category_slug or "").strip().lower()
    if slug == "windows-platform" or "windows" in slug:
        return "windows"
    if slug == "unix-platform" or "unix" in slug:
        return "unix"
    if slug == "network-platform" or "network" in slug:
        return "network"

    category = (category_name or "").strip().lower()
    if "windows" in category:
        return "windows"
    if "unix" in category:
        return "unix"
    if "network" in category:
        return "network"

    name = (os_name or "").strip().lower()
    if not name:
        return "linux"
    if "windows" in name or name in {"win", "win32", "win64"}:
        return "windows"
    if "network" in name or any(tok in name for tok in ("cisco", "juniper", "mikrotik", "huawei", "fortinet")):
        return "network"
    if any(
        tok in name
        for tok in ("freebsd", "openbsd", "netbsd", "solaris", "aix", "hp-ux", "macos", "darwin", "unix")
    ):
        return "unix"
    # Normalize "RHEL 8" / "Ubuntu" → linux
    slug_name = re.sub(r"[^a-z0-9]+", "-", name).strip("-")
    if slug_name in {"linux", "rhel", "centos", "rocky", "alma", "ubuntu", "debian", "suse", "sles", "oracle"}:
        return "linux"
    if "linux" in name or "rhel" in name or "ubuntu" in name or "debian" in name:
        return "linux"
    return host_platform(name)


def platforms_compatible(host_os_type: str | None, profile_plat: str) -> bool:
    host_plat = host_platform(host_os_type)
    if host_plat == "unknown" or profile_plat == "unknown":
        return True  # shortcut: do not block when metadata is missing
    return host_plat == profile_plat
