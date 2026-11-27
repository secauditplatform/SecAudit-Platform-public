"""Remote network device CLI access via Netmiko (fallback: Paramiko)."""

from __future__ import annotations

import logging
import tempfile
from dataclasses import dataclass
from pathlib import Path

from secaudit_core.enums import NetworkVendor
from secaudit_core.network_vendor_registry import vendor_profile

logger = logging.getLogger(__name__)


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
    password: str | None = None,
    vendor: NetworkVendor,
    commands: list[str],
    enable_password: str | None = None,
    private_key: str | None = None,
    key_passphrase: str | None = None,
    known_hosts_entry: str | None = None,
    timeout: int = 30,
) -> list[NetworkCommandResult]:
    profile = vendor_profile(vendor)
    try:
        from netmiko import ConnectHandler
    except ImportError as exc:
        raise RuntimeError("netmiko is required for remote network checks") from exc

    connect_params: dict = {
        "device_type": profile.netmiko_device_type,
        "host": hostname,
        "port": port,
        "username": username,
        "timeout": timeout,
        "conn_timeout": timeout,
    }
    if password:
        connect_params["password"] = password
    if enable_password and profile.uses_enable:
        connect_params["secret"] = enable_password

    key_path: Path | None = None
    known_hosts_path: Path | None = None
    tmp_dir: tempfile.TemporaryDirectory[str] | None = None
    try:
        if private_key or known_hosts_entry:
            tmp_dir = tempfile.TemporaryDirectory(prefix="secaudit-netmiko-")
            base = Path(tmp_dir.name)
            if private_key:
                key_path = base / "id_key"
                text = private_key if private_key.endswith("\n") else private_key + "\n"
                key_path.write_text(text, encoding="utf-8")
                key_path.chmod(0o600)
                connect_params["use_keys"] = True
                connect_params["key_file"] = str(key_path)
                if key_passphrase:
                    connect_params["passphrase"] = key_passphrase
                if not password:
                    connect_params.pop("password", None)
            if known_hosts_entry:
                known_hosts_path = base / "known_hosts"
                known_hosts_path.write_text(
                    known_hosts_entry if known_hosts_entry.endswith("\n") else known_hosts_entry + "\n",
                    encoding="utf-8",
                )
                known_hosts_path.chmod(0o600)
                connect_params["ssh_config_file"] = None
                connect_params["system_hostkeys"] = False
                connect_params["alt_host_keys"] = True
                connect_params["alt_key_file"] = str(known_hosts_path)

        results: list[NetworkCommandResult] = []
        with ConnectHandler(**connect_params) as connection:
            if enable_password and profile.uses_enable:
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
    finally:
        if tmp_dir is not None:
            tmp_dir.cleanup()


def fetch_running_config(
    *,
    hostname: str,
    port: int,
    username: str,
    password: str | None = None,
    vendor: NetworkVendor,
    enable_password: str | None = None,
    private_key: str | None = None,
    key_passphrase: str | None = None,
    known_hosts_entry: str | None = None,
) -> str:
    commands = list(vendor_profile(vendor).show_config_commands)
    results = run_network_commands(
        hostname=hostname,
        port=port,
        username=username,
        password=password,
        vendor=vendor,
        enable_password=enable_password,
        private_key=private_key,
        key_passphrase=key_passphrase,
        known_hosts_entry=known_hosts_entry,
        commands=commands,
    )
    if not results or not results[0].ok:
        raise RuntimeError(results[0].error if results else "No command output")
    return results[0].output
