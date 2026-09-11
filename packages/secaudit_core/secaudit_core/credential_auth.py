"""SSH credential secret helpers shared by API and workers."""

from __future__ import annotations

from secaudit_core.enums import CredentialType
from secaudit_core.secrets import decrypt_secret
from secaudit_core.settings import SecAuditSettings


def decrypt_credential_key_passphrase(cred, settings: SecAuditSettings | None = None) -> str | None:
    encrypted = getattr(cred, "encrypted_key_passphrase", None)
    if not encrypted:
        return None
    settings = settings or SecAuditSettings()
    return decrypt_secret(encrypted, settings)


def ssh_auth_from_credential(
    cred,
    secret: str,
    settings: SecAuditSettings | None = None,
) -> tuple[str | None, str | None, str | None]:
    """Return password, private_key, and optional key passphrase."""
    settings = settings or SecAuditSettings()
    password = secret if cred.credential_type == CredentialType.SSH_PASSWORD else None
    private_key = secret if cred.credential_type == CredentialType.SSH_KEY else None
    key_passphrase = decrypt_credential_key_passphrase(cred, settings) if private_key else None
    return password, private_key, key_passphrase
