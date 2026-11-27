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


FitVerdict = Literal["match", "version_mismatch", "distro_mismatch", "unknown_os"]
_GENERIC_OS_NAMES = frozenset({"", "linux", "windows", "unix", "network", "*", "any"})


def profile_fit(
    *,
    host_os_type: str | None,
    host_os_family: str | None,
    host_os_version: str | None,
    profile_os_name: str | None,
    profile_os_version: str | None,
    profile_name: str | None,
    profile_plat: str,
    category_slug: str | None,
    open_ports: list[int] | None = None,
) -> FitVerdict:
    """Family and version verdict. ``match`` is the only applicable result.

    A generic profile (no distro and no version) stays applicable when the coarse
    platform matches, including when the host OS is unknown. A named distro is
    not applicable until the host has that family.
    """
    slug = (category_slug or "").strip().lower()
    if slug == "services" and _known_service_profile(profile_name, profile_os_name):
        return _service_fit(profile_name, profile_os_name, open_ports)
    host_plat = host_platform(host_os_type)
    if profile_plat not in {"unknown", host_plat} and host_plat != "unknown":
        return "distro_mismatch"
    if _generic_os_profile(profile_os_name, profile_os_version):
        return "match"
    from secaudit_core.audit_flow_match import detect_family

    host_family = detect_family(
        " ".join(part for part in (host_os_family, host_os_type, host_os_version) if part)
    )
    if not host_family:
        return "unknown_os"
    profile_family = detect_family(
        " ".join(part for part in (profile_os_name, profile_os_version) if part)
    )
    if profile_family and host_family != profile_family:
        return "distro_mismatch"
    wanted = profile_os_version if _has_version(profile_os_version) else profile_os_name
    have = host_os_version if _has_version(host_os_version) else f"{host_os_family or ''} {host_os_type or ''}"
    return _version_fit(wanted, have)


def _has_version(value: str | None) -> bool:
    from secaudit_core.audit_flow_match import _version_tuple

    return bool(_version_tuple(value))


def _generic_os_profile(os_name: str | None, os_version: str | None) -> bool:
    from secaudit_core.audit_flow_match import detect_family

    if _has_version(os_version) or _has_version(os_name):
        return False
    name = (os_name or "").strip().lower()
    if name in _GENERIC_OS_NAMES:
        return True
    return detect_family(os_name or "") is None


def _version_fit(profile_version: str | None, host_version: str | None) -> FitVerdict:
    from secaudit_core.audit_flow_match import _version_tuple

    wanted = _version_tuple(profile_version)
    if not wanted:
        return "match"
    have = _version_tuple(host_version)
    if not have:
        return "unknown_os"
    width = min(len(wanted), len(have))
    if wanted[:width] != have[:width]:
        return "version_mismatch"
    return "match"


def _known_service_profile(profile_name: str | None, os_name: str | None) -> bool:
    from secaudit_core.audit_flow_match import _APP_SIGNATURES

    hay = f"{profile_name or ''} {os_name or ''}".lower()
    return any(any(name in hay for name in names) for _needles, _ports, names in _APP_SIGNATURES)


def _service_fit(
    profile_name: str | None,
    os_name: str | None,
    open_ports: list[int] | None,
) -> FitVerdict:
    from secaudit_core.audit_flow_match import rank_application_profiles

    if not open_ports:
        return "unknown_os"
    ranked = rank_application_profiles(
        services=None,
        open_ports=open_ports,
        profiles=[
            {
                "id": 0,
                "profile_name": profile_name or "",
                "os_name": os_name,
                "category_slug": "services",
            }
        ],
    )
    return "match" if ranked else "distro_mismatch"
