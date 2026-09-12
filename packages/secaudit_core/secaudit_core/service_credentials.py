"""Service-layer credentials (database, middleware) paired with OS host access."""

from __future__ import annotations

import re
import shlex

from secaudit_core.enums import CategoryType
from secaudit_core.secrets import decrypt_secret
from secaudit_core.settings import SecAuditSettings

_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def decrypt_credential_service_secret(cred, settings: SecAuditSettings | None = None) -> str | None:
    encrypted = getattr(cred, "encrypted_service_secret", None)
    if not encrypted:
        return None
    settings = settings or SecAuditSettings()
    return decrypt_secret(encrypted, settings)


def service_auth_from_credential(
    cred,
    settings: SecAuditSettings | None = None,
) -> tuple[str | None, str | None]:
    settings = settings or SecAuditSettings()
    username = (getattr(cred, "service_username", None) or "").strip() or None
    secret = decrypt_credential_service_secret(cred, settings)
    return username, secret


def service_env_from_credential(
    cred,
    settings: SecAuditSettings | None = None,
) -> dict[str, str]:
    """Environment variables injected into service/middleware audit scripts."""
    username, secret = service_auth_from_credential(cred, settings)
    if not username and not secret:
        return {}
    env: dict[str, str] = {}
    if username:
        env["SECAUDIT_SERVICE_USER"] = username
        env["resource_user"] = username
        env["DB_USER"] = username
        env["SERVICE_USER"] = username
    if secret:
        env["SECAUDIT_SERVICE_PASS"] = secret
        env["resource_pass"] = secret
        env["DB_PASS"] = secret
        env["SERVICE_PASS"] = secret
    return env


def profile_uses_service_credentials(category_type: CategoryType | None) -> bool:
    """OS profiles use host login only; service profiles need service credentials."""
    if category_type is None:
        return False
    return category_type != CategoryType.OS


def service_script_cli_suffix(env: dict[str, str] | None) -> str:
    """CLI flags expected by service audit scripts (-software_user/-software_password)."""
    if not env:
        return ""
    user = (
        env.get("DB_USER")
        or env.get("SECAUDIT_SERVICE_USER")
        or env.get("SERVICE_USER")
        or env.get("resource_user")
    )
    password = (
        env.get("DB_PASS")
        or env.get("SECAUDIT_SERVICE_PASS")
        or env.get("SERVICE_PASS")
        or env.get("resource_pass")
    )
    parts: list[str] = []
    if user:
        parts.extend(["-software_user", shlex.quote(user)])
    if password:
        parts.extend(["-software_password", shlex.quote(password)])
    return (" " + " ".join(parts)) if parts else ""


def shell_export_prefix(env: dict[str, str] | None) -> str:
    if not env:
        return ""
    exports: list[str] = []
    for key, value in env.items():
        if not _ENV_KEY_RE.fullmatch(key):
            raise ValueError(f"Invalid environment variable name: {key!r}")
        exports.append(f"export {key}={shlex.quote(value)}")
    return "; ".join(exports) + "; "


def powershell_env_prefix(env: dict[str, str] | None) -> str:
    if not env:
        return ""
    lines: list[str] = []
    for key, value in env.items():
        if not _ENV_KEY_RE.fullmatch(key):
            raise ValueError(f"Invalid environment variable name: {key!r}")
        safe = value.replace("'", "''")
        lines.append(f"$env:{key} = '{safe}'")
    return "\n".join(lines) + "\n"
