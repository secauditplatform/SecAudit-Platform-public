"""Shared inventory scan validation and nmap XML parsing."""

from __future__ import annotations

import ipaddress
import json
import re
import shlex
import xml.etree.ElementTree as ET
from typing import TypedDict

# Smallest allowed prefix length (largest network): /20 ≈ 4096 addresses.
MAX_CIDR_PREFIX_LEN = 20

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


def _validate_ipv4_network_prefix(net: ipaddress.IPv4Network) -> None:
    if net.prefixlen < MAX_CIDR_PREFIX_LEN:
        raise ValueError(
            f"Network too large (/{net.prefixlen}); maximum allowed is /{MAX_CIDR_PREFIX_LEN}"
        )


def validate_scan_target(target: str) -> str:
    cleaned = target.strip()
    if not cleaned or len(cleaned) > 256:
        raise ValueError("Target must be 1–256 characters")

    if "/" in cleaned:
        try:
            net = ipaddress.ip_network(cleaned, strict=False)
        except ValueError as exc:
            raise ValueError("Invalid CIDR notation") from exc
        if isinstance(net, ipaddress.IPv4Network):
            _validate_ipv4_network_prefix(net)
        return str(net)

    try:
        return str(ipaddress.ip_address(cleaned))
    except ValueError:
        pass

    if NMAP_RANGE_PATTERN.fullmatch(cleaned):
        return cleaned

    if HOSTNAME_PATTERN.fullmatch(cleaned):
        return cleaned

    raise ValueError(
        "Invalid target: use an IP, CIDR (e.g. 192.168.1.0/24), hostname, or nmap range"
    )


def expand_scan_target(target: str) -> list[str] | None:
    """Expand a single IP or IPv4 CIDR. None means nmap must interpret the target."""
    cleaned = target.strip()
    if "/" in cleaned:
        try:
            net = ipaddress.ip_network(cleaned, strict=False)
        except ValueError:
            return None
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
        ip: str | None = None
        hostname: str | None = None
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
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
        ip: str | None = None
        hostname: str | None = None
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                ip = addr.get("addr")
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
    return f"discovered-{ip.replace('.', '-')}"[:128]


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
