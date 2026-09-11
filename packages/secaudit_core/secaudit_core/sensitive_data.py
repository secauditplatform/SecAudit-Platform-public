"""Validation and recursive redaction for externally supplied configuration."""

from __future__ import annotations

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
        return _redact_url(value)
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
