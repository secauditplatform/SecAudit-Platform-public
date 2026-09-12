"""Tests for pluggable secrets backends (Fernet, Vault Transit, AWS KMS)."""

from __future__ import annotations

import base64
from unittest.mock import MagicMock, patch

import pytest

from secaudit_core.secrets import decrypt_secret, encrypt_secret
from secaudit_core.secrets_backend import (
    AWS_KMS_PREFIX,
    FERNET_PREFIX,
    VAULT_PREFIX,
    AwsKmsSecretsBackend,
    FernetSecretsBackend,
)
from secaudit_core.security import validate_production_secrets_backend
from secaudit_core.settings import SecAuditSettings


def _settings(**overrides) -> SecAuditSettings:
    return SecAuditSettings(**overrides)


def test_fernet_encrypt_decrypt_roundtrip():
    settings = _settings(secret_key="unit-test-secret-key-32chars!!")
    token = encrypt_secret("ssh-password", settings)
    assert token.startswith(FERNET_PREFIX)
    assert decrypt_secret(token, settings) == "ssh-password"


def test_fernet_dedicated_key_roundtrip():
    settings = _settings(
        secret_key="jwt-or-other-secret-key-32chars!",
        secrets_fernet_key="dedicated-fernet-key-material!!",
    )
    token = encrypt_secret("ssh-password", settings)
    assert decrypt_secret(token, settings) == "ssh-password"


def test_fernet_decrypt_falls_back_to_legacy_secret_key():
    legacy_settings = _settings(secret_key="legacy-secret-key-32characters!")
    legacy_token = encrypt_secret("old-secret", legacy_settings)
    rotated = _settings(
        secret_key="legacy-secret-key-32characters!",
        secrets_fernet_key="new-dedicated-fernet-key-32ch!!",
    )
    # Blob was encrypted with secret_key before dedicated key existed.
    assert decrypt_secret(legacy_token, rotated) == "old-secret"


def test_fernet_legacy_blob_without_prefix_still_decrypts():
    settings = _settings(secret_key="unit-test-secret-key-32chars!!")
    legacy = FernetSecretsBackend("unit-test-secret-key-32chars!!")
    # Simulate pre-migration blob stored without envelope prefix.
    raw_token = legacy.encrypt("legacy-value")[len(FERNET_PREFIX) :]
    assert decrypt_secret(raw_token, settings) == "legacy-value"


def test_validate_production_secrets_backend_rejects_fernet():
    with pytest.raises(RuntimeError, match="SECRETS_BACKEND=fernet is forbidden"):
        validate_production_secrets_backend(
            app_env="production",
            secrets_backend="fernet",
            secrets_fernet_allowed_in_production=False,
            vault_addr=None,
            vault_token=None,
            vault_token_file=None,
            aws_kms_key_id=None,
        )


def test_validate_production_secrets_backend_allows_fernet_opt_in():
    validate_production_secrets_backend(
        app_env="production",
        secrets_backend="fernet",
        secrets_fernet_allowed_in_production=True,
        vault_addr=None,
        vault_token=None,
        vault_token_file=None,
        aws_kms_key_id=None,
    )


def test_validate_production_secrets_backend_requires_vault_config():
    with pytest.raises(RuntimeError, match="VAULT_ADDR"):
        validate_production_secrets_backend(
            app_env="production",
            secrets_backend="vault",
            secrets_fernet_allowed_in_production=False,
            vault_addr=None,
            vault_token="token",
            vault_token_file=None,
            aws_kms_key_id=None,
        )


def test_validate_production_secrets_backend_requires_kms_key():
    with pytest.raises(RuntimeError, match="AWS_KMS_KEY_ID"):
        validate_production_secrets_backend(
            app_env="production",
            secrets_backend="aws_kms",
            secrets_fernet_allowed_in_production=False,
            vault_addr=None,
            vault_token=None,
            vault_token_file=None,
            aws_kms_key_id=None,
        )


@patch("secaudit_core.secrets_backend.httpx.Client")
def test_vault_transit_encrypt_decrypt(mock_client_cls):
    mock_client = MagicMock()
    mock_client_cls.return_value.__enter__.return_value = mock_client
    ciphertext = "vault:v1:abc123"
    mock_client.post.side_effect = [
        MagicMock(
            raise_for_status=MagicMock(),
            json=MagicMock(return_value={"data": {"ciphertext": ciphertext}}),
        ),
        MagicMock(
            raise_for_status=MagicMock(),
            json=MagicMock(
                return_value={"data": {"plaintext": base64.b64encode(b"vault-plain").decode()}}
            ),
        ),
    ]

    settings = _settings(
        secrets_backend="vault",
        vault_addr="http://vault:8200",
        vault_token="hvs.test",
    )
    token = encrypt_secret("vault-plain", settings)
    assert token == f"{VAULT_PREFIX}{ciphertext}"
    assert decrypt_secret(token, settings) == "vault-plain"


@patch.object(AwsKmsSecretsBackend, "_client")
def test_aws_kms_encrypt_decrypt(mock_client_method):
    kms = MagicMock()
    mock_client_method.return_value = kms
    blob = b"encrypted-by-kms"
    kms.encrypt.return_value = {"CiphertextBlob": blob}
    kms.decrypt.return_value = {"Plaintext": b"kms-secret"}

    settings = _settings(secrets_backend="aws_kms", aws_kms_key_id="arn:aws:kms:us-east-1:1:key/abc")
    token = encrypt_secret("kms-secret", settings)
    assert token.startswith(AWS_KMS_PREFIX)
    assert decrypt_secret(token, settings) == "kms-secret"
