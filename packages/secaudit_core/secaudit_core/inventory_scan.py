"""Shared inventory scan validation and nmap XML parsing."""

from __future__ import annotations

import ipaddress
import json
import re
import shlex
import socket
from defusedxml import ElementTree as ET
from typing import TypedDict

# Default smallest allowed prefix length (largest network): /20 ≈ 4096 addresses.
# Callers may pass a wider limit (smaller prefix number) for privileged roles.
MAX_CIDR_PREFIX_LEN = 20
# Absolute floor even for admins — /8 would be ~16M hosts and is never allowed.
MIN_CIDR_PREFIX_LEN_ABSOLUTE = 8
# A hostname is one target, not a subnet. More addresses than an AuditFlow
# target list would let one name stand in for a v4 prefix.
MAX_HOSTNAME_ADDRESSES = 16
IPV6_PREFIX_ERROR = (
    "IPv6 prefixes are not supported. Enter one IPv6 address or a hostname."
)

# Phase 2 uses nmap -F (fast scan): top 100 TCP ports per nmap's frequency ranking,
# including common services such as 22, 80, 443, 445, 3389, 8080, etc.
# -Pn skips a second ping (hosts already found by discovery). Timing/host-timeout
# keep /24 TCP connect scans from appearing hung for tens of minutes.
NMAP_DISCOVERY_ARGS = ("-sn",)
# Only ICMP/ARP replies count as ping-live. TCP RST from a firewall/NAT is "up"
# in default nmap -sn and must not enter the port-scan set.
ALIVE_DISCOVERY_REASONS = frozenset(
    {
        "echo-reply",
        "timestamp-reply",
        "netmask-reply",
        "arp-response",
        "in-arp-response",
        "syn-ack",
    }
)
NMAP_PORT_SCAN_ARGS = (
    "-Pn",
    "-sT",
    "-F",
    "-T4",
    "--max-retries",
    "1",
    "--host-timeout",
    "30s",
    "--open",
)

DEFAULT_NMAP_FLAGS_JSON = json.dumps(
    {"mode": "default", "discovery": list(NMAP_DISCOVERY_ARGS), "port_scan": list(NMAP_PORT_SCAN_ARGS)}
)

HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
)

# Nmap octet/range targets, e.g. 192.168.1.1-254 or 192.168.1-5.*
NMAP_RANGE_PATTERN = re.compile(
    r"^(\d{1,3}|\d{1,3}-\d{1,3})(\.(\d{1,3}|\d{1,3}-\d{1,3})){0,3}(\.\*)?$"
)

_DANGEROUS_CHARS = set(";|&$`<>(){}\\\"\n\r\t")
_BLOCKED_FLAGS = frozenset(
    {
        "--script",
        "-o",
        "-oA",
        "-oG",
        "-oN",
        "-oS",
        "-oX",
        "-oL",
        "--datadir",
        "--resume",
        "--iflist",
        "-iL",
        "-iR",
        "--proxies",
        "--proxy",
    }
)
_ALLOWED_FLAG = re.compile(r"^--[a-zA-Z][a-zA-Z0-9\-]*$")
_ALLOWED_SHORT = re.compile(r"^-[a-zA-Z]+$")
_ALLOWED_PORT_SPEC = re.compile(r"^[\d,\-]+$")
_ALLOWED_TIMING = re.compile(r"^-T[0-5]$")
_FLAGS_WITH_VALUE = frozenset(
    {"-p", "--top-ports", "-PA", "-PS", "-PU", "-PO", "--max-retries", "--host-timeout", "--min-rate", "--max-rate"}
)


class DiscoveredHost(TypedDict):
    ip: str
    hostname: str | None


class HostPortInfo(TypedDict):
    ip: str
    hostname: str | None
    open_ports: list[int]


class ScanCancelledError(Exception):
    """Raised when a scan is cancelled via Redis flag."""


def _validate_ipv4_network_prefix(
    net: ipaddress.IPv4Network,
    *,
    max_prefix_len: int = MAX_CIDR_PREFIX_LEN,
) -> None:
    """Reject networks wider than ``max_prefix_len`` (smaller prefix number = larger net)."""
    limit = max(int(max_prefix_len), MIN_CIDR_PREFIX_LEN_ABSOLUTE)
    if net.prefixlen < limit:
        raise ValueError(
            f"Network too large (/{net.prefixlen}); maximum allowed is /{limit}"
        )


def validate_scan_target(target: str, *, max_prefix_len: int | None = None) -> str:
    cleaned = target.strip()
    if not cleaned or len(cleaned) > 256:
        raise ValueError("Target must be 1–256 characters")

    prefix_limit = MAX_CIDR_PREFIX_LEN if max_prefix_len is None else int(max_prefix_len)

    if "/" in cleaned:
        try:
            net = ipaddress.ip_network(cleaned, strict=False)
        except ValueError as exc:
            raise ValueError("Invalid CIDR notation") from exc
        if isinstance(net, ipaddress.IPv6Network):
            # A /64 is not another /24. Reject it before nmap starts.
            raise ValueError(IPV6_PREFIX_ERROR)
        if isinstance(net, ipaddress.IPv4Network):
            _validate_ipv4_network_prefix(net, max_prefix_len=prefix_limit)
        _assert_network_not_blocked(net)
        return str(net)

    try:
        addr = ipaddress.ip_address(cleaned)
    except ValueError:
        pass
    else:
        _assert_address_not_blocked(addr)
        return str(addr)

    if NMAP_RANGE_PATTERN.fullmatch(cleaned):
        _assert_nmap_range_not_blocked(cleaned)
        return cleaned

    if HOSTNAME_PATTERN.fullmatch(cleaned):
        if cleaned.lower() in {"localhost", "metadata.google.internal"}:
            raise ValueError(f"Scan target host is not allowed: {cleaned}")
        return cleaned

    raise ValueError(
        "Invalid target: use an IP, CIDR (e.g. 192.168.1.0/24), hostname, or nmap range"
    )


def _assert_address_not_blocked(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    if addr.is_loopback or addr.is_link_local or addr.is_unspecified or addr.is_multicast:
        raise ValueError(f"Scan target address is not allowed: {addr}")
    # Cloud metadata / APIPA
    if addr in ipaddress.ip_network("169.254.0.0/16") or addr in ipaddress.ip_network("fe80::/10"):
        raise ValueError(f"Scan target address is not allowed: {addr}")


def _assert_network_not_blocked(net: ipaddress.IPv4Network | ipaddress.IPv6Network) -> None:
    blocked = (
        ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"),
        ipaddress.ip_network("::1/128"),
        ipaddress.ip_network("fe80::/10"),
    )
    for item in blocked:
        if net.version == item.version and (net.subnet_of(item) or item.subnet_of(net) or net == item):
            raise ValueError(f"Scan target network is not allowed: {net}")
    if net.is_loopback or getattr(net, "is_link_local", False):
        raise ValueError(f"Scan target network is not allowed: {net}")


def _assert_nmap_range_not_blocked(target: str) -> None:
    # Conservative: reject obvious loopback / link-local prefixes in nmap ranges.
    lowered = target.lower()
    if lowered.startswith("127.") or lowered.startswith("169.254."):
        raise ValueError(f"Scan target range is not allowed: {target}")


def expand_scan_target(target: str) -> list[str] | None:
    """Expand a single IP or IPv4 CIDR. None means nmap must interpret the target."""
    cleaned = target.strip()
    if "/" in cleaned:
        try:
            net = ipaddress.ip_network(cleaned, strict=False)
        except ValueError:
            return None
        if isinstance(net, ipaddress.IPv6Network):
            raise ValueError(IPV6_PREFIX_ERROR)
        if isinstance(net, ipaddress.IPv4Network):
            return [str(ip) for ip in net.hosts()]
        return None
    try:
        return [str(ipaddress.ip_address(cleaned))]
    except ValueError:
        return None


def _validate_nmap_token(token: str) -> None:
    if token in _BLOCKED_FLAGS or token.startswith("--script"):
        raise ValueError(f"Flag not allowed: {token}")
    if token.startswith("-p") and len(token) > 2:
        if not re.match(r"^-p[\d,\-]+$", token):
            raise ValueError(f"Invalid port spec: {token}")
        return
    if _ALLOWED_TIMING.match(token) or token in {"-sn", "-sT", "-sS", "-sU", "-F", "-Pn", "-n", "-R", "--open", "--reason"}:
        return
    if _ALLOWED_SHORT.match(token) or _ALLOWED_FLAG.match(token):
        return
    if _ALLOWED_PORT_SPEC.match(token):
        return
    raise ValueError(f"Invalid nmap flag: {token}")


def validate_nmap_flags(flags: str) -> list[str]:
    """Parse and validate optional custom nmap flags (no shell injection)."""
    cleaned = flags.strip()
    if not cleaned:
        return []
    if len(cleaned) > 256:
        raise ValueError("nmap flags must be at most 256 characters")
    if any(ch in cleaned for ch in _DANGEROUS_CHARS):
        raise ValueError("nmap flags contain invalid characters")

    try:
        tokens = shlex.split(cleaned)
    except ValueError as exc:
        raise ValueError("Invalid nmap flags syntax") from exc

    if not tokens or len(tokens) > 15:
        raise ValueError("nmap flags must contain 1–15 tokens")

    validated: list[str] = []
    i = 0
    while i < len(tokens):
        token = tokens[i]
        _validate_nmap_token(token)
        validated.append(token)
        if token in _FLAGS_WITH_VALUE or (token.startswith("--") and i + 1 < len(tokens) and not tokens[i + 1].startswith("-")):
            if i + 1 >= len(tokens):
                raise ValueError(f"Flag {token} requires a value")
            value = tokens[i + 1]
            if token == "-p" or token == "--top-ports":
                if not _ALLOWED_PORT_SPEC.match(value):
                    raise ValueError(f"Invalid value for {token}: {value}")
            elif not re.match(r"^[\w.,:/\-]+$", value):
                raise ValueError(f"Invalid value for {token}")
            validated.append(value)
            i += 2
            continue
        i += 1
    return validated


def encode_nmap_flags(custom_args: list[str] | None) -> str:
    if custom_args:
        return json.dumps({"mode": "custom", "flags": custom_args})
    return DEFAULT_NMAP_FLAGS_JSON


def decode_nmap_flags(raw: str | None) -> dict:
    if not raw:
        return json.loads(DEFAULT_NMAP_FLAGS_JSON)
    return json.loads(raw)


def format_nmap_flags_display(raw: str | None) -> str:
    data = decode_nmap_flags(raw)
    if data.get("mode") == "custom":
        return " ".join(data.get("flags", []))
    discovery = " ".join(data.get("discovery", list(NMAP_DISCOVERY_ARGS)))
    port_scan = " ".join(data.get("port_scan", list(NMAP_PORT_SCAN_ARGS)))
    return f"{discovery}; {port_scan}"


def _load_nmap_xml_root(xml_text: str) -> ET.Element:
    """Parse nmap XML, tolerating leading/trailing noise around the nmaprun document."""
    cleaned = xml_text.strip()
    if not cleaned:
        raise ValueError("nmap produced empty XML output")

    start = cleaned.find("<nmaprun")
    end = cleaned.rfind("</nmaprun>")
    if start != -1 and end != -1:
        cleaned = cleaned[start : end + len("</nmaprun>")]
    elif start != -1:
        # Incomplete document — still try from nmaprun (better error from ET).
        cleaned = cleaned[start:]

    try:
        return ET.fromstring(cleaned)
    except ET.ParseError as exc:
        raise ValueError(f"Failed to parse nmap XML: {exc}") from exc


def parse_nmap_discovery_xml(xml_text: str, *, skip_unreliable: bool = False) -> list[DiscoveredHost]:
    """Parse ping-scan (-sn) output: all hosts that respond."""
    root = _load_nmap_xml_root(xml_text)
    discovered: list[DiscoveredHost] = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        reason = (status.get("reason") or "").strip().lower()
        if skip_unreliable and reason not in ALIVE_DISCOVERY_REASONS:
            continue
        ip = _ip_from_address_elements(host)
        hostname: str | None = None
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                hostname = hn.get("name")
        if ip:
            discovered.append({"ip": ip, "hostname": hostname})
    return discovered


def parse_nmap_port_scan_xml(xml_text: str) -> dict[str, HostPortInfo]:
    """Parse port-scan output: open TCP ports per host."""
    root = _load_nmap_xml_root(xml_text)
    by_ip: dict[str, HostPortInfo] = {}
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = _ip_from_address_elements(host)
        hostname: str | None = None
        hostnames = host.find("hostnames")
        if hostnames is not None:
            hn = hostnames.find("hostname")
            if hn is not None:
                hostname = hn.get("name")
        if not ip:
            continue

        open_ports: list[int] = []
        ports = host.find("ports")
        if ports is not None:
            for port in ports.findall("port"):
                if port.get("protocol") != "tcp":
                    continue
                state = port.find("state")
                if state is not None and state.get("state") == "open":
                    try:
                        open_ports.append(int(port.get("portid", "0")))
                    except ValueError:
                        continue

        open_ports.sort()
        by_ip[ip] = {"ip": ip, "hostname": hostname, "open_ports": open_ports}
    return by_ip


def host_name_for_ip(ip: str, resolved_hostname: str | None) -> str:
    if resolved_hostname:
        return resolved_hostname[:128]
    label = ip.replace(":", "-").replace(".", "-")
    return f"discovered-{label}"[:128]


def bracket_ipv6_host(host: str) -> str:
    """Wrap an IPv6 address so a URL does not treat its colons as a port."""
    text = host.strip()
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return text
    if addr.version == 6:
        return f"[{addr}]"
    return str(addr)


def nmap_calls_for_target(target: str) -> list[tuple[list[str], list[str]]]:
    """Split one scan target into nmap invocations.

    Each item is ``(extra_flags, targets)``. IPv4 and IPv6 cannot share one
    nmap process. A single IPv6 address is passed with ``-6``. A hostname that
    resolves to AAAA is passed as those addresses, not left as an unparsed
    name. An IPv6 prefix is rejected. A name that resolves to more addresses
    than the target-list ceiling is rejected so it cannot stand in for a v4 subnet.
    """
    cleaned = target.strip()
    if "/" in cleaned or NMAP_RANGE_PATTERN.fullmatch(cleaned):
        if "/" in cleaned:
            try:
                net = ipaddress.ip_network(cleaned, strict=False)
            except ValueError:
                return [([], [cleaned])]
            if isinstance(net, ipaddress.IPv6Network):
                raise ValueError(IPV6_PREFIX_ERROR)
            return [([], [str(net)])]
        return [([], [cleaned])]
    try:
        addr = ipaddress.ip_address(cleaned)
    except ValueError:
        return _calls_for_hostname(cleaned)
    if addr.version == 6:
        return [(["-6"], [str(addr)])]
    return [([], [str(addr)])]


def nmap_address_groups(addresses: list[str]) -> list[tuple[list[str], list[str]]]:
    """Group concrete addresses so a later port scan uses ``-6`` only for IPv6."""
    v4: list[str] = []
    v6: list[str] = []
    for item in addresses:
        try:
            addr = ipaddress.ip_address(item)
        except ValueError:
            v4.append(item)
            continue
        if addr.version == 6:
            v6.append(str(addr))
        else:
            v4.append(str(addr))
    groups: list[tuple[list[str], list[str]]] = []
    if v4:
        groups.append(([], v4))
    if v6:
        groups.append((["-6"], v6))
    return groups


def _calls_for_hostname(hostname: str) -> list[tuple[list[str], list[str]]]:
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return [([], [hostname])]
    v4: list[str] = []
    v6: list[str] = []
    for info in infos:
        raw = str(info[4][0]).split("%", 1)[0]
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError:
            continue
        bucket = v6 if addr.version == 6 else v4
        text = str(addr)
        if text not in bucket:
            try:
                _assert_address_not_blocked(addr)
            except ValueError:
                continue
            bucket.append(text)
    if not v6:
        # IPv4-only names stay a single nmap target, as before.
        return [([], [hostname])]
    if len(v4) + len(v6) > MAX_HOSTNAME_ADDRESSES:
        raise ValueError(
            "Hostname resolves to too many addresses; enter one address instead of a network"
        )
    if not v4 and not v6:
        raise ValueError(f"Scan target host is not allowed: {hostname}")
    calls: list[tuple[list[str], list[str]]] = []
    if v4:
        calls.append(([], v4))
    if v6:
        calls.append((["-6"], v6))
    return calls


def _ip_from_address_elements(host: ET.Element) -> str | None:
    for addr in host.findall("address"):
        if addr.get("addrtype") not in {"ipv4", "ipv6"}:
            continue
        value = (addr.get("addr") or "").strip()
        if value:
            return value
    return None


def infer_host_defaults(open_ports: list[int]) -> tuple[int, str]:
    port_set = set(open_ports)
    if port_set & {3389, 445, 5985, 5986}:
        for preferred in (3389, 445, 5985, 5986):
            if preferred in port_set:
                return preferred, "windows"
    if 22 in port_set:
        return 22, "linux"
    if 443 in port_set or 80 in port_set:
        return 443 if 443 in port_set else 80, "network"
    return open_ports[0], "linux"
