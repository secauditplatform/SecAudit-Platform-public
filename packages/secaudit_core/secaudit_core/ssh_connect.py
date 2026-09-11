"""Shared asyncssh connect kwargs for API/worker executors."""

from __future__ import annotations

from secaudit_core.settings import SecAuditSettings


def _known_hosts_from_entry(entry: str):
    """Convert a known_hosts line/block into an AsyncSSH-compatible value.

    AsyncSSH treats ``str`` as a *filesystem path* and ``bytes`` as file
    contents. Host-scanned fingerprints are content, never paths.
    """
    text = entry.strip()
    if not text:
        return None
    # Prefer the dedicated parser when available; fall back to raw bytes.
    try:
        import asyncssh

        return asyncssh.import_known_hosts(text)
    except Exception:
        return (text + "\n").encode("utf-8")


def build_ssh_connect_kwargs(
    *,
    host: str,
    port: int,
    username: str,
    password: str | None,
    private_key: str | None,
    settings: SecAuditSettings | None = None,
    known_hosts_entry: str | None = None,
    key_passphrase: str | None = None,
) -> dict:
    settings = settings or SecAuditSettings()
    kwargs: dict = {
        "host": host,
        "port": port,
        "username": username,
    }

    if known_hosts_entry and known_hosts_entry.strip():
        kwargs["known_hosts"] = _known_hosts_from_entry(known_hosts_entry)
    elif settings.ssh_strict_host_key_checking_effective:
        if settings.ssh_known_hosts_path:
            # Path string is intentional: AsyncSSH opens this as a file.
            kwargs["known_hosts"] = settings.ssh_known_hosts_path
    else:
        kwargs["known_hosts"] = None

    if private_key:
        import asyncssh

        kwargs["client_keys"] = [
            asyncssh.import_private_key(private_key, passphrase=key_passphrase or None)
        ]
    elif password:
        kwargs["password"] = password
    else:
        raise ValueError("SSH credential requires password or private key")

    return kwargs
