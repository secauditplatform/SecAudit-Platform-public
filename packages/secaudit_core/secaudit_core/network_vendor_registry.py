"""Declarative Netmiko / show-config registry keyed by NetworkVendor."""

from __future__ import annotations

from dataclasses import dataclass

from secaudit_core.enums import NetworkVendor


@dataclass(frozen=True)
class NetworkVendorProfile:
    vendor: NetworkVendor
    netmiko_device_type: str
    show_config_commands: tuple[str, ...]
    os_family: str
    uses_enable: bool = False


_PROFILES: dict[NetworkVendor, NetworkVendorProfile] = {
    NetworkVendor.CISCO_IOS: NetworkVendorProfile(
        NetworkVendor.CISCO_IOS, "cisco_ios", ("show running-config",), "ios", True
    ),
    NetworkVendor.CISCO_NXOS: NetworkVendorProfile(
        NetworkVendor.CISCO_NXOS, "cisco_nxos", ("show running-config",), "nxos", True
    ),
    NetworkVendor.CISCO_ASA: NetworkVendorProfile(
        NetworkVendor.CISCO_ASA, "cisco_asa", ("show running-config",), "asa", True
    ),
    NetworkVendor.JUNIPER_JUNOS: NetworkVendorProfile(
        NetworkVendor.JUNIPER_JUNOS,
        "juniper_junos",
        ("show configuration | display set",),
        "junos",
    ),
    NetworkVendor.ARISTA_EOS: NetworkVendorProfile(
        NetworkVendor.ARISTA_EOS, "arista_eos", ("show running-config",), "eos", True
    ),
    NetworkVendor.HUAWEI: NetworkVendorProfile(
        NetworkVendor.HUAWEI, "huawei", ("display current-configuration",), "vrp"
    ),
    NetworkVendor.H3C: NetworkVendorProfile(
        NetworkVendor.H3C, "hp_comware", ("display current-configuration",), "comware"
    ),
    NetworkVendor.FORTINET: NetworkVendorProfile(
        NetworkVendor.FORTINET, "fortinet", ("show full-configuration",), "fortios"
    ),
    NetworkVendor.PALO_ALTO: NetworkVendorProfile(
        NetworkVendor.PALO_ALTO, "paloalto_panos", ("show config running",), "panos"
    ),
    NetworkVendor.CHECK_POINT: NetworkVendorProfile(
        NetworkVendor.CHECK_POINT, "checkpoint_gaia", ("show configuration",), "gaia"
    ),
    NetworkVendor.ELTEX: NetworkVendorProfile(
        NetworkVendor.ELTEX, "cisco_ios", ("show running-config",), "eltex", True
    ),
    NetworkVendor.MIKROTIK: NetworkVendorProfile(
        NetworkVendor.MIKROTIK, "mikrotik_routeros", ("/export",), "routeros"
    ),
    NetworkVendor.USERGATE: NetworkVendorProfile(
        NetworkVendor.USERGATE, "linux", ("show configuration",), "usergate"
    ),
    NetworkVendor.CONTINENT: NetworkVendorProfile(
        NetworkVendor.CONTINENT, "autodetect", ("show running-config",), "continent"
    ),
    NetworkVendor.QTECH: NetworkVendorProfile(
        NetworkVendor.QTECH, "cisco_ios", ("show running-config",), "qtech", True
    ),
    NetworkVendor.GENERIC: NetworkVendorProfile(
        NetworkVendor.GENERIC, "autodetect", ("show running-config",), "generic"
    ),
}

_TEXT_MARKERS: tuple[tuple[tuple[str, ...], NetworkVendor], ...] = (
    (("mikrotik", "routeros"), NetworkVendor.MIKROTIK),
    (("eltex", "mes-", "esr-"), NetworkVendor.ELTEX),
    (("usergate",), NetworkVendor.USERGATE),
    (("continent", "континент"), NetworkVendor.CONTINENT),
    (("qtech",), NetworkVendor.QTECH),
    (("junos", "juniper"), NetworkVendor.JUNIPER_JUNOS),
    (("nx-os", "nxos", "nexus"), NetworkVendor.CISCO_NXOS),
    (("adaptive security", "cisco asa"), NetworkVendor.CISCO_ASA),
    (("arista", "eos"), NetworkVendor.ARISTA_EOS),
    (("fortigate", "fortios", "fortinet"), NetworkVendor.FORTINET),
    (("palo alto", "pan-os", "panos"), NetworkVendor.PALO_ALTO),
    (("check point", "checkpoint", "gaia"), NetworkVendor.CHECK_POINT),
    (("huawei", "vrp"), NetworkVendor.HUAWEI),
    (("h3c", "comware"), NetworkVendor.H3C),
    (("cisco ios", "cisco ios xe", "ios-xe"), NetworkVendor.CISCO_IOS),
)

# Enterprise OID prefixes (SNMP sysObjectID) → vendor.
_ENTERPRISE_OIDS: tuple[tuple[str, NetworkVendor], ...] = (
    ("1.3.6.1.4.1.9.", NetworkVendor.CISCO_IOS),
    ("1.3.6.1.4.1.2636.", NetworkVendor.JUNIPER_JUNOS),
    ("1.3.6.1.4.1.30065.", NetworkVendor.ARISTA_EOS),
    ("1.3.6.1.4.1.2011.", NetworkVendor.HUAWEI),
    ("1.3.6.1.4.1.25506.", NetworkVendor.H3C),
    ("1.3.6.1.4.1.12356.", NetworkVendor.FORTINET),
    ("1.3.6.1.4.1.25461.", NetworkVendor.PALO_ALTO),
    ("1.3.6.1.4.1.2620.", NetworkVendor.CHECK_POINT),
    ("1.3.6.1.4.1.14988.", NetworkVendor.MIKROTIK),
    ("1.3.6.1.4.1.35265.", NetworkVendor.ELTEX),
    ("1.3.6.1.4.1.27514.", NetworkVendor.QTECH),
)


def vendor_profile(vendor: NetworkVendor) -> NetworkVendorProfile:
    return _PROFILES.get(vendor, _PROFILES[NetworkVendor.GENERIC])


def os_family_for(vendor: NetworkVendor) -> str:
    return vendor_profile(vendor).os_family


def parse_network_vendor(value: object | None) -> NetworkVendor | None:
    if value is None or value == "":
        return None
    if isinstance(value, NetworkVendor):
        return value
    try:
        return NetworkVendor(str(value).strip().lower())
    except ValueError:
        return None


def resolve_host_vendor(host: object) -> NetworkVendor:
    """Prefer Host.network_vendor; never invent Cisco IOS."""
    stored = parse_network_vendor(getattr(host, "network_vendor", None))
    if stored is not None:
        return stored
    inferred = infer_vendor_from_text(
        getattr(host, "name", None),
        getattr(host, "hostname", None),
        getattr(host, "os_family", None),
    )
    return inferred or NetworkVendor.GENERIC


def infer_vendor_from_text(*parts: object | None) -> NetworkVendor | None:
    blob = " ".join(str(part) for part in parts if part).casefold()
    if not blob:
        return None
    for markers, vendor in _TEXT_MARKERS:
        if any(marker in blob for marker in markers):
            return vendor
    if "cisco" in blob:
        return NetworkVendor.CISCO_IOS
    return None


def infer_vendor_from_snmp(
    sys_descr: str | None = None,
    sys_object_id: str | None = None,
) -> NetworkVendor | None:
    oid = (sys_object_id or "").strip()
    if oid:
        normalized = oid if oid.startswith("1.") else f"1.{oid}" if oid.startswith("3.6.") else oid
        for prefix, vendor in _ENTERPRISE_OIDS:
            if normalized.startswith(prefix) or oid.startswith(prefix.removeprefix("1.")):
                return vendor
    return infer_vendor_from_text(sys_descr, sys_object_id)


def infer_vendor_from_filename(filename: str) -> NetworkVendor:
    return infer_vendor_from_text(filename) or (
        NetworkVendor.CISCO_IOS
        if filename.lower().endswith(".cfg")
        else NetworkVendor.GENERIC
    )
