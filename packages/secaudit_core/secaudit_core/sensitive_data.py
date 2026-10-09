"""Validation and recursive redaction for externally supplied configuration."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

REDACTED = "[REDACTED]"
_SENSITIVE_PARTS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "private_key",
    "webhook_url",
)

# Free-text patterns commonly leaked into executor logs / exceptions.
# A match replaces the secret and keeps the surrounding line (nmap banners stay).
_SENSITIVE_TEXT_PATTERNS = (
    re.compile(r"(?i)(password|passwd|passphrase|secret|token|api[_-]?key)\s*[=:]\s*([^\s,;]+)"),
    re.compile(r"(?i)(ansible_password|ansible_ssh_pass|resource_pass|db_pass)\s*[=:]\s*([^\s,;]+)"),
    re.compile(r"(?i)(-software_password|--password|--passphrase)\s+(\S+)"),
    re.compile(r"(?i)\b(password|passwd|passphrase)\s+\d+\s+(\S+)"),
    re.compile(r"(?i)\b(authorization)\s*[:=]\s*((?:bearer\s+|basic\s+)?\S+)"),
    re.compile(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        re.DOTALL,
    ),
    re.compile(r"\d{6,16}:[A-Za-z0-9_-]{30,64}(?![A-Za-z0-9_-])"),
)


def is_sensitive_key(key: object) -> bool:
    normalized = str(key).strip().lower().replace("-", "_")
    return any(part in normalized for part in _SENSITIVE_PARTS)


def _redact_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return value
    if not parsed.scheme or not parsed.netloc:
        return value
    netloc = parsed.netloc
    if parsed.username is not None or parsed.password is not None:
        host = parsed.hostname or ""
        if parsed.port:
            host = f"{host}:{parsed.port}"
        netloc = f"{REDACTED}@{host}"
    query = urlencode(
        [
            (key, REDACTED if is_sensitive_key(key) else item)
            for key, item in parse_qsl(parsed.query, keep_blank_values=True)
        ]
    )
    redacted = urlunsplit((parsed.scheme, netloc, parsed.path, query, parsed.fragment))
    return redacted


def _redact_text(value: str) -> str:
    text = _redact_url(value)
    for pattern in _SENSITIVE_TEXT_PATTERNS:
        if pattern.groups == 0:
            text = pattern.sub(REDACTED, text)
        elif pattern.groups >= 2:
            text = pattern.sub(lambda m: f"{m.group(1)}={REDACTED}", text)
        else:
            text = pattern.sub(REDACTED, text)
    return text


def redact_live_log_frame(raw: str) -> str:
    """Redact secrets in a live-log frame before it is stored or sent on a socket."""
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        redacted = redact_sensitive(raw)
        return redacted if isinstance(redacted, str) else raw
    if isinstance(data, dict) and isinstance(data.get("message"), str):
        cleaned = redact_sensitive(data["message"])
        data["message"] = cleaned if isinstance(cleaned, str) else data["message"]
        return json.dumps(data, ensure_ascii=False)
    redacted = redact_sensitive(raw)
    return redacted if isinstance(redacted, str) else raw


def redact_sensitive(value: Any) -> Any:
    """Return a recursively redacted copy suitable for responses, logs and audit."""
    if isinstance(value, Mapping):
        return {
            str(key): REDACTED if is_sensitive_key(key) else redact_sensitive(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_sensitive(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_sensitive(item) for item in value)
    if isinstance(value, str):
        return _redact_text(value)
    return value


def find_secret_paths(value: Any, *, prefix: str = "config_json") -> list[str]:
    """Find keys and credential-bearing URLs that must use encrypted fields."""
    found: list[str] = []
    if isinstance(value, Mapping):
        for key, item in value.items():
            path = f"{prefix}.{key}"
            if is_sensitive_key(key):
                found.append(path)
            else:
                found.extend(find_secret_paths(item, prefix=path))
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            found.extend(find_secret_paths(item, prefix=f"{prefix}[{index}]"))
    elif isinstance(value, str) and _redact_url(value) != value:
        found.append(prefix)
    return found


def reject_secret_config(value: dict | None) -> dict | None:
    paths = find_secret_paths(value or {})
    if paths:
        joined = ", ".join(paths[:5])
        raise ValueError(f"Secrets are not allowed in config_json; use the secret field ({joined})")
    return value
