"""Service-layer credentials (database, middleware) paired with OS host access."""

from __future__ import annotations

import shlex

from secaudit_core.enums import CategoryType
from secaudit_core.secrets import decrypt_secret
from secaudit_core.settings import SecAuditSettings


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
    """Deprecated: service passwords must not appear on remote argv.

    Credentials are injected via environment (``shell_export_prefix`` /
    ``powershell_env_prefix`` / env file). Always returns an empty string.
    """
    return ""


def shell_export_prefix(env: dict[str, str] | None) -> str:
    if not env:
        return ""
    exports = [f"export {key}={shlex.quote(value)}" for key, value in env.items()]
    return "; ".join(exports) + "; "


def powershell_env_prefix(env: dict[str, str] | None) -> str:
    if not env:
        return ""
    lines: list[str] = []
    for key, value in env.items():
        safe = value.replace("'", "''")
        lines.append(f"$env:{key} = '{safe}'")
    return "\n".join(lines) + "\n"
