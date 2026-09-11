"""SSH host key fingerprint helpers (OpenSSH SHA256 format)."""

from __future__ import annotations

import base64
import hashlib
import re
import subprocess


_FINGERPRINT_RE = re.compile(r"^SHA256:([A-Za-z0-9+/]+={0,2})$", re.IGNORECASE)


def normalize_ssh_fingerprint(value: str) -> str:
    text = (value or "").strip()
    if not text:
        raise ValueError("SSH fingerprint is empty")
    if text.upper().startswith("SHA256:"):
        body = text.split(":", 1)[1]
        return f"SHA256:{body.rstrip('=')}"
    if _FINGERPRINT_RE.match(f"SHA256:{text}"):
        return f"SHA256:{text.rstrip('=')}"
    # Bare base64 body without prefix
    return f"SHA256:{text.rstrip('=')}"


def fingerprint_from_known_hosts_line(line: str) -> str:
    parts = line.strip().split()
    if len(parts) < 3:
        raise ValueError("Invalid known_hosts line")

    key_type = None
    key_b64 = None
    for idx, part in enumerate(parts[1:], start=1):
        if part.startswith(("ssh-", "ecdsa-", "sk-")):
            key_type = part
            if idx + 1 < len(parts):
                key_b64 = parts[idx + 1]
            break
    if not key_type or not key_b64:
        raise ValueError("Could not parse SSH public key from known_hosts line")

    raw = base64.b64decode(key_b64.encode("ascii"))
    digest = hashlib.sha256(raw).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def verify_or_pin_host_key(
    *,
    hostname: str,
    key_type: str,
    key_b64: str,
    expected_fingerprint: str | None = None,
) -> tuple[str, str]:
    """Return (fingerprint, known_hosts_line), or raise on a pin mismatch."""
    entry = f"{hostname} {key_type} {key_b64}"
    fingerprint = fingerprint_from_known_hosts_line(entry)
    if expected_fingerprint:
        expected = normalize_ssh_fingerprint(expected_fingerprint)
        if fingerprint != expected:
            raise ValueError(f"SSH host key mismatch for {hostname}")
    return fingerprint, entry


def scan_ssh_host_key(hostname: str, port: int = 22, *, timeout: int = 15) -> tuple[str, str]:
    """Fetch host keys via ssh-keyscan. Returns (fingerprint, known_hosts_line)."""
    host = hostname.strip()
    if not host:
        raise ValueError("Hostname is required")

    result = subprocess.run(
        ["ssh-keyscan", "-p", str(port), "-T", "10", host],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if result.returncode != 0 and not result.stdout.strip():
        stderr = (result.stderr or "").strip()
        raise RuntimeError(stderr or f"ssh-keyscan failed with code {result.returncode}")

    lines = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if not lines:
        raise RuntimeError("ssh-keyscan returned no host keys")

    entry = lines[0]
    return fingerprint_from_known_hosts_line(entry), entry
