"""Host/network collectors for pre-remediation backups."""

from __future__ import annotations


def read_network_running_config(
    *,
    hostname: str,
    port: int,
    username: str,
    password: str | None,
    private_key: str | None,
    vendor,
    key_passphrase: str | None = None,
    known_hosts_entry: str | None = None,
    enable_password: str | None = None,
) -> bytes:
    from app.executors.network_exec import fetch_running_config

    text = fetch_running_config(
        hostname=hostname,
        port=port or 22,
        username=username,
        password=password,
        vendor=vendor,
        private_key=private_key,
        key_passphrase=key_passphrase,
        known_hosts_entry=known_hosts_entry,
        enable_password=enable_password,
    )
    return (text or "").encode("utf-8", errors="replace")
