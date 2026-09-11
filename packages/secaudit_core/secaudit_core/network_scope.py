"""Network vs standard job scope validation and profile classification."""

from __future__ import annotations

from secaudit_core.enums import JobScope, NetworkCheckMode, NetworkVendor
from secaudit_core.models import Host, Profile

NETWORK_PLATFORM_SLUG = "network-platform"


def profile_is_network(profile: Profile | None) -> bool:
    if profile is None or profile.category is None:
        return False
    return profile.category.slug == NETWORK_PLATFORM_SLUG


def host_is_network(host: Host) -> bool:
    return (host.os_type or "").strip().lower() == "network"


def assert_scope_matches_profile(scope: JobScope, profile: Profile | None) -> None:
    is_network = profile_is_network(profile)
    if scope == JobScope.NETWORK and not is_network:
        raise ValueError("Network jobs require a network-platform profile")
    if scope == JobScope.STANDARD and is_network:
        raise ValueError("Standard jobs cannot use network-platform profiles")


def assert_network_hosts(hosts: list[Host]) -> None:
    for host in hosts:
        if not host_is_network(host):
            raise ValueError(f"Host {host.name} is not a network device (os_type=network required)")


def assert_standard_hosts(hosts: list[Host]) -> None:
    for host in hosts:
        if host_is_network(host):
            raise ValueError(f"Host {host.name} is a network device; use Network Operations")


def default_network_check_mode() -> NetworkCheckMode:
    return NetworkCheckMode.BOTH


def infer_vendor_from_filename(filename: str) -> NetworkVendor:
    lowered = filename.lower()
    if "junos" in lowered or "juniper" in lowered:
        return NetworkVendor.JUNIPER_JUNOS
    if "nxos" in lowered or "nexus" in lowered:
        return NetworkVendor.CISCO_NXOS
    if "asa" in lowered:
        return NetworkVendor.CISCO_ASA
    if "eos" in lowered or "arista" in lowered:
        return NetworkVendor.ARISTA_EOS
    if "forti" in lowered:
        return NetworkVendor.FORTINET
    if "palo" in lowered:
        return NetworkVendor.PALO_ALTO
    if "checkpoint" in lowered or "check_point" in lowered:
        return NetworkVendor.CHECK_POINT
    if "huawei" in lowered:
        return NetworkVendor.HUAWEI
    if "h3c" in lowered:
        return NetworkVendor.H3C
    if "cisco" in lowered or lowered.endswith(".cfg"):
        return NetworkVendor.CISCO_IOS
    return NetworkVendor.GENERIC
