"""Remote network device CLI access via Netmiko (fallback: Paramiko)."""

from __future__ import annotations

import logging
from dataclasses import dataclass

from secaudit_core.enums import NetworkVendor

logger = logging.getLogger(__name__)

VENDOR_TO_NETMIKO = {
    NetworkVendor.CISCO_IOS: "cisco_ios",
    NetworkVendor.CISCO_NXOS: "cisco_nxos",
    NetworkVendor.CISCO_ASA: "cisco_asa",
    NetworkVendor.JUNIPER_JUNOS: "juniper_junos",
    NetworkVendor.ARISTA_EOS: "arista_eos",
    NetworkVendor.HUAWEI: "huawei",
    NetworkVendor.H3C: "hp_comware",
    NetworkVendor.FORTINET: "fortinet",
    NetworkVendor.PALO_ALTO: "paloalto_panos",
    NetworkVendor.CHECK_POINT: "checkpoint_gaia",
    NetworkVendor.GENERIC: "autodetect",
}


@dataclass
class NetworkCommandResult:
    command: str
    output: str
    ok: bool
    error: str | None = None


def run_network_commands(
    *,
    hostname: str,
    port: int,
    username: str,
    password: str,
    vendor: NetworkVendor,
    commands: list[str],
    enable_password: str | None = None,
    timeout: int = 30,
) -> list[NetworkCommandResult]:
    device_type = VENDOR_TO_NETMIKO.get(vendor, "autodetect")
    try:
        from netmiko import ConnectHandler
    except ImportError as exc:
        raise RuntimeError("netmiko is required for remote network checks") from exc

    connect_params = {
        "device_type": device_type,
        "host": hostname,
        "port": port,
        "username": username,
        "password": password,
        "timeout": timeout,
        "conn_timeout": timeout,
    }
    if enable_password:
        connect_params["secret"] = enable_password

    results: list[NetworkCommandResult] = []
    with ConnectHandler(**connect_params) as connection:
        if enable_password:
            connection.enable()
        for command in commands:
            try:
                output = connection.send_command(command, read_timeout=timeout)
                results.append(NetworkCommandResult(command=command, output=output, ok=True))
            except Exception as exc:
                logger.warning("Network command failed on %s: %s", hostname, exc)
                results.append(
                    NetworkCommandResult(
                        command=command,
                        output="",
                        ok=False,
                        error=str(exc),
                    )
                )
    return results


def fetch_running_config(
    *,
    hostname: str,
    port: int,
    username: str,
    password: str,
    vendor: NetworkVendor,
    enable_password: str | None = None,
) -> str:
    if vendor == NetworkVendor.JUNIPER_JUNOS:
        commands = ["show configuration | display set"]
    elif vendor in {NetworkVendor.CISCO_IOS, NetworkVendor.CISCO_NXOS}:
        commands = ["show running-config"]
    elif vendor == NetworkVendor.FORTINET:
        commands = ["show full-configuration"]
    else:
        commands = ["show running-config"]
    results = run_network_commands(
        hostname=hostname,
        port=port,
        username=username,
        password=password,
        vendor=vendor,
        enable_password=enable_password,
        commands=commands,
    )
    if not results or not results[0].ok:
        raise RuntimeError(results[0].error if results else "No command output")
    return results[0].output
