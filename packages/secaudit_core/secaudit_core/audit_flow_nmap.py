"""Parse nmap XML for AuditFlow: ports, banners, OS fingerprint, host identity."""

from __future__ import annotations

from typing import TypedDict
from xml.etree.ElementTree import Element

from secaudit_core.inventory_scan import (
    _load_nmap_xml_root,
    infer_host_defaults,
)

AUDITFLOW_PORT_SPEC = (
    "22,445,3389,5985,5986,23,830,21,25,53,80,88,110,111,135,139,143,389,443,465,587,636,993,995,"
    "1433,1521,2049,2376,3128,3306,5432,5900,6379,6443,8000,8080,8291,8443,9042,9090,9200,11211,27017"
)
AUDITFLOW_MANAGEMENT_PORTS = frozenset({22, 23, 445, 3389, 5985, 5986, 830})
AUDITFLOW_WINDOWS_PORTS = frozenset({139, 445, 3389})

# Phase 1: ICMP + ARP + TCP SYN to common ports. Default -sn only pings 80/443;
# Docker/NAT RSTs those and nmap would mark the whole /24 up. skip_unreliable
# keeps echo/arp/syn-ack and drops reset. Slow LAN hosts (~1s RTT) need a longer
# max-rtt than nmap T3/T4 defaults or they vanish on a /24 sweep.
NMAP_AUDITFLOW_DISCOVERY = (
    "-sn",
    "-n",
    "-PE",
    "-PP",
    "-PS22,80,443,445,3389,5985",
    "--max-retries",
    "2",
    "--initial-rtt-timeout",
    "500ms",
    "--max-rtt-timeout",
    "2000ms",
    "--max-parallelism",
    "32",
)
# Phase 2: OS + services on ping-live hosts only. host-timeout keeps a filtered
# box from stalling the whole chunk; SSH/RDP are probed first in the port list.
NMAP_AUDITFLOW_IDENTITY = (
    "-Pn",
    "-n",
    "-sT",
    "-sV",
    "--version-intensity",
    "5",
    "-O",
    "--osscan-guess",
    "-p",
    AUDITFLOW_PORT_SPEC,
    "--script",
    "smb-os-discovery,rdp-ntlm-info",
    "--script-timeout",
    "15s",
    "-T4",
    "--max-retries",
    "1",
    "--host-timeout",
    "60s",
    "--open",
)
NMAP_AUDITFLOW_IDENTITY_NO_OS = tuple(
    token for token in NMAP_AUDITFLOW_IDENTITY if token not in {"-O", "--osscan-guess"}
)
# Kept for tests / fallbacks that still refer to the split flags.
NMAP_AUDITFLOW_PORTS = (
    "-Pn",
    "-sT",
    "-F",
    "-T4",
    "--max-retries",
    "2",
    "--open",
)
NMAP_AUDITFLOW_SERVICE = NMAP_AUDITFLOW_IDENTITY_NO_OS
NMAP_AUDITFLOW_OS = (
    "-Pn",
    "-sT",
    "-O",
    "--osscan-guess",
    "-T4",
    "--max-retries",
    "2",
)
PORT_SCAN_CHUNK_SIZE = 8
_GENERIC_OS_LABELS = frozenset(
    {"", "linux", "linux or unix", "windows", "network device", "unix"}
)


def nmap_service_args(*, syn: bool = False) -> list[str]:
    args = list(NMAP_AUDITFLOW_SERVICE)
    if syn:
        return ["-sS" if token == "-sT" else token for token in args]
    return args


def host_from_open_ports(
    ip: str, hostname: str | None, open_ports: list[int]
) -> AuditFlowNmapHost:
    ports = sorted({int(p) for p in open_ports})
    os_guess = None
    if ports:
        _, platform = infer_host_defaults(ports)
        os_guess = {"linux": "Linux", "windows": "Windows", "network": "Network device"}.get(platform)
    return {
        "ip": ip,
        "hostname": hostname,
        "open_ports": ports,
        "services": [],
        "os_guess": os_guess,
        "os_accuracy": 35 if os_guess else 0,
        "mac_vendor": None,
        "device_type": None,
        "scripts": {},
    }


def has_management_port(open_ports: list[int] | None) -> bool:
    return bool(set(open_ports or []) & AUDITFLOW_MANAGEMENT_PORTS)


def needs_os_fingerprint(host: AuditFlowNmapHost | None) -> bool:
    if not host or not host.get("open_ports"):
        return False
    guess = (host.get("os_guess") or "").strip().lower()
    return guess in _GENERIC_OS_LABELS


def needs_windows_script(host: AuditFlowNmapHost | None) -> bool:
    if not host:
        return False
    ports = set(host.get("open_ports") or [])
    if not ports & AUDITFLOW_WINDOWS_PORTS:
        return False
    guess = (host.get("os_guess") or "").strip().lower()
    return guess in _GENERIC_OS_LABELS or "windows" in guess


_OS_SCRIPT_IDS = frozenset({"smb-os-discovery", "rdp-ntlm-info"})
_WIN_NTLM_RELEASE = (
    (26100, "Windows 11 / Server 2025"),
    (22621, "Windows 11"),
    (22000, "Windows 11"),
    (20348, "Windows Server 2022"),
    (19041, "Windows 10"),
    (17763, "Windows Server 2019"),
    (14393, "Windows Server 2016"),
    (9600, "Windows 8.1 / Server 2012 R2"),
    (9200, "Windows 8 / Server 2012"),
    (7601, "Windows 7 / Server 2008 R2"),
)


class ServiceBanner(TypedDict):
    port: int
    name: str
    product: str
    extra: str
    version: str
    ostype: str


class AuditFlowNmapHost(TypedDict, total=False):
    ip: str
    hostname: str | None
    open_ports: list[int]
    services: list[ServiceBanner]
    os_guess: str | None
    os_accuracy: int
    mac_vendor: str | None
    device_type: str | None
    scripts: dict[str, str]


def parse_nmap_service_xml(xml_text: str) -> dict[str, AuditFlowNmapHost]:
    root = _load_nmap_xml_root(xml_text)
    by_ip: dict[str, AuditFlowNmapHost] = {}
    for host in root.findall("host"):
        parsed = _parse_host(host)
        if parsed:
            by_ip[parsed["ip"]] = parsed
    return by_ip


def merge_auditflow_hosts(
    primary: AuditFlowNmapHost | None, secondary: AuditFlowNmapHost | None
) -> AuditFlowNmapHost | None:
    if primary is None and secondary is None:
        return None
    if primary is None:
        secondary["os_guess"] = compose_os_guess(secondary)
        secondary["hostname"] = compose_hostname(secondary)
        return secondary
    if secondary is None:
        primary["os_guess"] = compose_os_guess(primary)
        primary["hostname"] = compose_hostname(primary)
        return primary
    ports = sorted(set(primary.get("open_ports") or []) | set(secondary.get("open_ports") or []))
    services = list(primary.get("services") or [])
    seen = {(s["port"], s.get("name")) for s in services}
    for svc in secondary.get("services") or []:
        key = (svc["port"], svc.get("name"))
        if key not in seen:
            services.append(svc)
            seen.add(key)
    scripts = dict(primary.get("scripts") or {})
    scripts.update(secondary.get("scripts") or {})
    acc_a = int(primary.get("os_accuracy") or 0)
    acc_b = int(secondary.get("os_accuracy") or 0)
    if acc_b > acc_a:
        os_guess = secondary.get("os_guess") or primary.get("os_guess")
        os_accuracy = acc_b
    else:
        os_guess = primary.get("os_guess") or secondary.get("os_guess")
        os_accuracy = acc_a
    merged: AuditFlowNmapHost = {
        "ip": primary.get("ip") or secondary.get("ip") or "",
        "hostname": primary.get("hostname") or secondary.get("hostname"),
        "open_ports": ports,
        "services": services,
        "os_guess": os_guess,
        "os_accuracy": os_accuracy,
        "mac_vendor": primary.get("mac_vendor") or secondary.get("mac_vendor"),
        "device_type": primary.get("device_type") or secondary.get("device_type"),
        "scripts": scripts,
    }
    merged["os_guess"] = compose_os_guess(merged)
    merged["hostname"] = compose_hostname(merged)
    return merged


def compose_os_guess(host: AuditFlowNmapHost) -> str | None:
    """Best unauthenticated OS label: nmap -O, then NSE, then banners, then MAC/ports."""
    accuracy = int(host.get("os_accuracy") or 0)
    nmap_os = (host.get("os_guess") or "").strip()
    script_os = _os_from_scripts(host.get("scripts") or {})
    banner_os = _os_from_services(host.get("services") or [])
    specific = script_os or banner_os
    if nmap_os and accuracy >= 80:
        if specific and _more_specific(specific, nmap_os):
            return specific[:256]
        return nmap_os[:256]
    if script_os:
        return script_os[:256]
    if nmap_os and accuracy >= 50:
        if specific and _more_specific(specific, nmap_os):
            return specific[:256]
        return nmap_os[:256]
    if banner_os:
        return banner_os[:256]
    if nmap_os:
        return nmap_os[:256]
    vendor = (host.get("mac_vendor") or "").strip()
    device = (host.get("device_type") or "").strip()
    ports = set(host.get("open_ports") or [])
    if vendor and device:
        return f"{vendor} {device}"[:256]
    if vendor:
        return f"{vendor} device"[:256]
    if ports & {3389, 445, 139, 5985, 5986}:
        return "Windows"
    if 8291 in ports:
        return "MikroTik RouterOS"
    if ports & {23, 830}:
        return "Network device"
    if 22 in ports:
        return "Linux or Unix"
    return None


def compose_hostname(host: AuditFlowNmapHost) -> str | None:
    ptr = (host.get("hostname") or "").strip() or None
    scripts = host.get("scripts") or {}
    for key in ("fqdn", "dns_computer_name", "computer_name", "netbios_computer_name"):
        value = (scripts.get(key) or "").strip()
        if value:
            return value[:256]
    return ptr[:256] if ptr else None


def parse_nmap_gnmap_hosts(text: str) -> list[tuple[str, str | None]]:
    """Parse nmap grepable (-oG) lines written as each host completes."""
    found: list[tuple[str, str | None]] = []
    seen: set[str] = set()
    for line in text.splitlines():
        if not line.startswith("Host:"):
            continue
        if "Status: Down" in line:
            continue
        if "Status: Up" not in line and "Ports:" not in line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        ip = parts[1]
        if ip in seen:
            continue
        hostname: str | None = None
        rest = line[len("Host:") :].strip()
        if "(" in rest and ")" in rest:
            inner = rest[rest.find("(") + 1 : rest.find(")")]
            hostname = inner.strip() or None
        seen.add(ip)
        found.append((ip, hostname))
    return found


def services_blob(host: AuditFlowNmapHost) -> str:
    parts = []
    if host.get("os_guess"):
        parts.append(host["os_guess"])
    vendor = host.get("mac_vendor")
    if vendor:
        parts.append(f"mac-vendor {vendor}")
    device = host.get("device_type")
    if device:
        parts.append(f"device-type {device}")
    for key, value in (host.get("scripts") or {}).items():
        if value:
            parts.append(f"{key} {value}")
    for svc in host.get("services") or []:
        parts.append(
            " ".join(
                part
                for part in (
                    f"{svc['port']}/{svc['name']}",
                    svc.get("product") or "",
                    svc.get("version") or "",
                    svc.get("extra") or "",
                    svc.get("ostype") or "",
                )
                if part
            )
        )
    return "\n".join(parts)


def _parse_host(host: Element) -> AuditFlowNmapHost | None:
    status = host.find("status")
    if status is None or status.get("state") != "up":
        return None
    ip: str | None = None
    mac_vendor: str | None = None
    for addr in host.findall("address"):
        kind = addr.get("addrtype")
        if kind == "ipv4":
            ip = addr.get("addr")
        elif kind == "mac":
            mac_vendor = addr.get("vendor") or mac_vendor
    if not ip:
        return None

    hostname = _hostname_from_xml(host)
    open_ports: list[int] = []
    services: list[ServiceBanner] = []
    scripts: dict[str, str] = {}
    ports = host.find("ports")
    if ports is not None:
        for port in ports.findall("port"):
            if port.get("protocol") != "tcp":
                continue
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            try:
                port_id = int(port.get("portid", "0"))
            except ValueError:
                continue
            open_ports.append(port_id)
            svc = port.find("service")
            services.append(
                {
                    "port": port_id,
                    "name": (svc.get("name") if svc is not None else "") or "",
                    "product": (svc.get("product") if svc is not None else "") or "",
                    "extra": (svc.get("extrainfo") if svc is not None else "") or "",
                    "version": (svc.get("version") if svc is not None else "") or "",
                    "ostype": (svc.get("ostype") if svc is not None else "") or "",
                }
            )
            for script in port.findall("script"):
                scripts.update(_script_fields(script))
        open_ports.sort()

    hostscript = host.find("hostscript")
    if hostscript is not None:
        for script in hostscript.findall("script"):
            scripts.update(_script_fields(script))

    os_guess, os_accuracy, device_type = _os_from_nmap_os(host.find("os"))
    parsed: AuditFlowNmapHost = {
        "ip": ip,
        "hostname": hostname,
        "open_ports": open_ports,
        "services": services,
        "os_guess": os_guess,
        "os_accuracy": os_accuracy,
        "mac_vendor": mac_vendor,
        "device_type": device_type,
        "scripts": scripts,
    }
    parsed["os_guess"] = compose_os_guess(parsed)
    parsed["hostname"] = compose_hostname(parsed)
    return parsed


def _hostname_from_xml(host: Element) -> str | None:
    hostnames = host.find("hostnames")
    if hostnames is None:
        return None
    ptr = None
    any_name = None
    for hn in hostnames.findall("hostname"):
        name = (hn.get("name") or "").strip()
        if not name:
            continue
        any_name = any_name or name
        if (hn.get("type") or "").upper() == "PTR":
            ptr = name
    return ptr or any_name


def _os_from_nmap_os(os_el: Element | None) -> tuple[str | None, int, str | None]:
    if os_el is None:
        return None, 0, None
    best_name = None
    best_acc = -1
    device_type = None
    for match in os_el.findall("osmatch"):
        try:
            acc = int(match.get("accuracy") or 0)
        except ValueError:
            acc = 0
        name = (match.get("name") or "").strip()
        if name and acc > best_acc:
            best_acc = acc
            best_name = name
        if device_type is None:
            osclass = match.find("osclass")
            if osclass is not None:
                device_type = osclass.get("type")
    if best_name:
        return best_name, max(best_acc, 0), device_type
    osclass = os_el.find("osclass")
    if osclass is not None:
        vendor = (osclass.get("vendor") or "").strip()
        family = (osclass.get("osfamily") or "").strip()
        gen = (osclass.get("osgen") or "").strip()
        device_type = osclass.get("type") or device_type
        try:
            acc = int(osclass.get("accuracy") or 0)
        except ValueError:
            acc = 0
        label = " ".join(part for part in (vendor, family, gen) if part)
        return (label or None), acc, device_type
    return None, 0, device_type


def _script_fields(script: Element) -> dict[str, str]:
    script_id = (script.get("id") or "").strip()
    fields: dict[str, str] = {}
    if script_id not in _OS_SCRIPT_IDS and script_id != "nbstat":
        return fields
    for elem in script.findall("elem"):
        key = (elem.get("key") or "").strip().lower().replace(" ", "_")
        text = "".join(elem.itertext()).strip()
        if key and text:
            fields[key] = text
    output = (script.get("output") or "").strip()
    if script_id:
        fields[script_id] = output or fields.get(script_id, "")
    return fields


def _os_from_scripts(scripts: dict[str, str]) -> str | None:
    os_line = (scripts.get("os") or "").strip()
    lan = (scripts.get("lan_manager") or "").strip()
    if os_line:
        return f"{os_line} {lan}".strip() if lan and lan not in os_line else os_line
    product = (scripts.get("product_version") or scripts.get("os_version") or "").strip()
    if product:
        mapped = _windows_from_ntlm(product)
        if mapped:
            return mapped
        return f"Windows {product}"
    smb = (scripts.get("smb-os-discovery") or "").strip()
    if smb:
        for line in smb.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("os:"):
                return stripped.split(":", 1)[1].strip() or None
    return None


def _windows_from_ntlm(product: str) -> str | None:
    parts = product.split(".")
    if len(parts) >= 3 and parts[0] == "10" and parts[1] == "0":
        try:
            build = int(parts[2])
        except ValueError:
            return None
        for threshold, label in _WIN_NTLM_RELEASE:
            if build >= threshold:
                return label
    if product.startswith("6.3"):
        return "Windows 8.1 / Server 2012 R2"
    if product.startswith("6.2"):
        return "Windows 8 / Server 2012"
    if product.startswith("6.1"):
        return "Windows 7 / Server 2008 R2"
    return None


def _more_specific(candidate: str, baseline: str) -> bool:
    lower_c = candidate.lower()
    lower_b = baseline.lower().strip()
    if (
        lower_b in {"linux", "unix", "windows", "network device"}
        or lower_b.startswith("linux ")
        or lower_b.startswith("windows ")
    ):
        return any(
            token in lower_c
            for token in (
                "ubuntu",
                "debian",
                "red hat",
                "centos",
                "alma",
                "rocky",
                "suse",
                "opensuse",
                "fedora",
                "astra",
                "openwrt",
                "xiaomi",
                "miwifi",
                "windows 10",
                "windows 11",
                "windows server",
                "cisco",
                "routeros",
                "junos",
            )
        )
    return False


_APP_SERVICE_NAMES = frozenset(
    {
        "http",
        "https",
        "http-proxy",
        "http-alt",
        "nagios-nsca",
        "nsca",
        "nrpe",
        "mysql",
        "postgresql",
        "redis",
        "mongodb",
        "smtp",
        "imap",
        "pop3",
        "domain",
        "ftp",
    }
)
_OS_PRODUCT_LABELS = (
    ("xiaoqiang", "Xiaomi MiWiFi"),
    ("miwifi", "Xiaomi MiWiFi"),
    ("openwrt", "OpenWrt"),
    ("uhttpd", "OpenWrt"),
    ("routeros", "MikroTik RouterOS"),
    ("cisco ios", "Cisco IOS"),
    ("junos", "Juniper Junos"),
)


def _looks_like_os_label(text: str) -> bool:
    blob = text.lower()
    if not blob or blob[:1].isdigit() and "/" in blob[:6]:
        return False
    tokens = (
        "linux",
        "ubuntu",
        "debian",
        "windows",
        "cisco",
        "ios",
        "routeros",
        "junos",
        "openwrt",
        "suse",
        "fedora",
        "centos",
        "redhat",
        "alma",
        "rocky",
        "xiaomi",
        "mikrotik",
        "freebsd",
        "darwin",
    )
    return any(token in blob for token in tokens)


def _os_from_product(product: str, ostype: str) -> str | None:
    blob = f"{product} {ostype}".lower()
    for needle, label in _OS_PRODUCT_LABELS:
        if needle in blob:
            return label
    if ostype and _looks_like_os_label(ostype) and not product:
        return ostype
    if ostype and product and _looks_like_os_label(ostype) and _looks_like_os_label(product):
        return f"{ostype} ({product})"
    return None


def _os_from_services(services: list[ServiceBanner]) -> str | None:
    ranked: list[str] = []
    for svc in services:
        name = (svc.get("name") or "").lower()
        extra = (svc.get("extra") or "").strip()
        ostype = (svc.get("ostype") or "").strip()
        product = (svc.get("product") or "").strip()
        extra_os = extra.split(";")[0].strip() if extra else ""
        if extra_os and _looks_like_os_label(extra_os):
            ranked.append(extra_os)
            continue
        product_os = _os_from_product(product, ostype)
        if product_os:
            ranked.append(product_os)
            continue
        if name in _APP_SERVICE_NAMES:
            continue
        if ostype and _looks_like_os_label(ostype):
            ranked.append(ostype)
    return ranked[0] if ranked else None
