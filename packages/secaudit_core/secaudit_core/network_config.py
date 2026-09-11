"""Parse running-config / startup-config text for multi-vendor network devices."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from secaudit_core.enums import CheckStatus, NetworkVendor


@dataclass
class ConfigCheckResult:
    rule_tech_name: str
    status: CheckStatus
    message: str


@dataclass
class ParsedNetworkConfig:
    vendor: NetworkVendor
    hostname: str | None = None
    lines: list[str] = field(default_factory=list)
    checks: list[ConfigCheckResult] = field(default_factory=list)


def parse_network_config(content: str, vendor: NetworkVendor) -> ParsedNetworkConfig:
    text = content.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in text.split("\n") if line.strip()]
    parsed = ParsedNetworkConfig(vendor=vendor, lines=lines)
    parsed.hostname = _extract_hostname(lines, vendor)
    parsed.checks = _run_baseline_checks(lines, vendor, parsed.hostname)
    return parsed


def _extract_hostname(lines: list[str], vendor: NetworkVendor) -> str | None:
    patterns: list[str]
    if vendor == NetworkVendor.JUNIPER_JUNOS:
        patterns = [r"^host-name\s+(\S+);"]
    elif vendor in {NetworkVendor.CISCO_IOS, NetworkVendor.CISCO_NXOS, NetworkVendor.CISCO_ASA}:
        patterns = [r"^hostname\s+(\S+)"]
    elif vendor == NetworkVendor.ARISTA_EOS:
        patterns = [r"^hostname\s+(\S+)"]
    elif vendor == NetworkVendor.FORTINET:
        patterns = [r'^set\s+hostname\s+"?([^"\s]+)"?']
    else:
        patterns = [r"^hostname\s+(\S+)", r"^host-name\s+(\S+);"]
    for line in lines:
        for pattern in patterns:
            match = re.match(pattern, line.strip(), re.IGNORECASE)
            if match:
                return match.group(1)
    return None


def _run_baseline_checks(
    lines: list[str], vendor: NetworkVendor, hostname: str | None
) -> list[ConfigCheckResult]:
    joined = "\n".join(lines).lower()
    checks: list[ConfigCheckResult] = []

    checks.append(
        ConfigCheckResult(
            rule_tech_name="NET_HOSTNAME_SET",
            status=CheckStatus.PASS if hostname else CheckStatus.FAIL,
            message=f"hostname={hostname}" if hostname else "hostname is not configured",
        )
    )

    if vendor in {NetworkVendor.CISCO_IOS, NetworkVendor.CISCO_NXOS, NetworkVendor.CISCO_ASA}:
        has_aaa = "aaa new-model" in joined or "aaa authentication" in joined
        checks.append(
            ConfigCheckResult(
                rule_tech_name="NET_AAA_ENABLED",
                status=CheckStatus.PASS if has_aaa else CheckStatus.FAIL,
                message="AAA configuration present" if has_aaa else "AAA not configured",
            )
        )
        has_ssh = "transport input ssh" in joined or "ip ssh version" in joined
        checks.append(
            ConfigCheckResult(
                rule_tech_name="NET_SSH_ENABLED",
                status=CheckStatus.PASS if has_ssh else CheckStatus.FAIL,
                message="SSH transport configured" if has_ssh else "SSH hardening not found",
            )
        )
    elif vendor == NetworkVendor.JUNIPER_JUNOS:
        has_root_auth = "root-authentication" in joined
        checks.append(
            ConfigCheckResult(
                rule_tech_name="NET_ROOT_AUTH",
                status=CheckStatus.PASS if has_root_auth else CheckStatus.FAIL,
                message="root-authentication configured" if has_root_auth else "missing root-authentication",
            )
        )
    else:
        checks.append(
            ConfigCheckResult(
                rule_tech_name="NET_CONFIG_NON_EMPTY",
                status=CheckStatus.PASS if len(lines) >= 5 else CheckStatus.FAIL,
                message=f"{len(lines)} configuration lines parsed",
            )
        )

    return checks


def generate_remediation_config(
    vendor: NetworkVendor,
    *,
    hostname: str | None = None,
    commands: list[str] | None = None,
) -> str:
    """Build a downloadable config snippet for manual application on device."""
    lines: list[str] = []
    if vendor in {NetworkVendor.CISCO_IOS, NetworkVendor.CISCO_NXOS, NetworkVendor.CISCO_ASA}:
        lines.append("configure terminal")
        if hostname:
            lines.append(f"hostname {hostname}")
        for cmd in commands or []:
            lines.append(cmd)
        lines.append("end")
        lines.append("write memory")
    elif vendor == NetworkVendor.JUNIPER_JUNOS:
        if hostname:
            lines.append(f"set system host-name {hostname}")
        for cmd in commands or []:
            lines.append(cmd)
        lines.append("commit")
    else:
        lines.append(f"! Remediation config for {vendor.value}")
        if hostname:
            lines.append(f"hostname {hostname}")
        lines.extend(commands or [])
    return "\n".join(lines) + "\n"
