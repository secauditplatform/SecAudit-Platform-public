from secaudit_core.secrets_backend import (
    create_secrets_backend,
    decrypt_with_fallback,
)
from secaudit_core.settings import SecAuditSettings


def encrypt_secret(plain: str, settings: SecAuditSettings) -> str:
    return create_secrets_backend(settings).encrypt(plain)


def decrypt_secret(token: str, settings: SecAuditSettings) -> str:
    return decrypt_with_fallback(token, settings)
