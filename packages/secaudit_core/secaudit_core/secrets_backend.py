"""Pluggable secrets backends for data-at-rest encryption (BYO-KMS / Vault)."""

from __future__ import annotations

import base64
import hashlib
import logging
from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
from cryptography.fernet import Fernet, InvalidToken

if TYPE_CHECKING:
    from secaudit_core.settings import SecAuditSettings

logger = logging.getLogger(__name__)

FERNET_PREFIX = "fernet:"
VAULT_PREFIX = "vault:"
AWS_KMS_PREFIX = "awskms:"


class SecretsBackendKind(str, Enum):
    FERNET = "fernet"
    VAULT = "vault"
    AWS_KMS = "aws_kms"


class SecretsBackend(ABC):
    @abstractmethod
    def encrypt(self, plain: str) -> str: ...

    @abstractmethod
    def decrypt(self, token: str) -> str: ...


def _fernet_from_secret_key(secret_key: str) -> Fernet:
    digest = hashlib.sha256(secret_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


class FernetSecretsBackend(SecretsBackend):
    def __init__(self, secret_key: str) -> None:
        self._fernet = _fernet_from_secret_key(secret_key)

    def encrypt(self, plain: str) -> str:
        token = self._fernet.encrypt(plain.encode()).decode()
        return f"{FERNET_PREFIX}{token}"

    def decrypt(self, token: str) -> str:
        payload = token[len(FERNET_PREFIX) :] if token.startswith(FERNET_PREFIX) else token
        try:
            return self._fernet.decrypt(payload.encode()).decode()
        except InvalidToken as exc:
            raise ValueError("Failed to decrypt credential") from exc


class VaultTransitSecretsBackend(SecretsBackend):
    def __init__(
        self,
        *,
        addr: str,
        token: str,
        mount: str = "transit",
        key: str = "secaudit",
        timeout: float = 10.0,
    ) -> None:
        self._addr = addr.rstrip("/")
        self._token = token
        self._mount = mount.strip("/")
        self._key = key
        self._timeout = timeout

    def _headers(self) -> dict[str, str]:
        return {"X-Vault-Token": self._token}

    def encrypt(self, plain: str) -> str:
        url = f"{self._addr}/v1/{self._mount}/encrypt/{self._key}"
        payload = {"plaintext": base64.b64encode(plain.encode()).decode()}
        with httpx.Client(timeout=self._timeout) as client:
            response = client.post(url, json=payload, headers=self._headers())
            response.raise_for_status()
            ciphertext = response.json()["data"]["ciphertext"]
        return f"{VAULT_PREFIX}{ciphertext}"

    def decrypt(self, token: str) -> str:
        ciphertext = token[len(VAULT_PREFIX) :] if token.startswith(VAULT_PREFIX) else token
        url = f"{self._addr}/v1/{self._mount}/decrypt/{self._key}"
        with httpx.Client(timeout=self._timeout) as client:
            response = client.post(
                url,
                json={"ciphertext": ciphertext},
                headers=self._headers(),
            )
            response.raise_for_status()
            plaintext_b64 = response.json()["data"]["plaintext"]
        return base64.b64decode(plaintext_b64).decode()


class AwsKmsSecretsBackend(SecretsBackend):
    def __init__(self, *, key_id: str, region: str) -> None:
        self._key_id = key_id
        self._region = region

    def _client(self):
        import boto3

        return boto3.client("kms", region_name=self._region)

    def encrypt(self, plain: str) -> str:
        response = self._client().encrypt(
            KeyId=self._key_id,
            Plaintext=plain.encode(),
        )
        blob = base64.b64encode(response["CiphertextBlob"]).decode()
        return f"{AWS_KMS_PREFIX}{blob}"

    def decrypt(self, token: str) -> str:
        blob_b64 = token[len(AWS_KMS_PREFIX) :] if token.startswith(AWS_KMS_PREFIX) else token
        response = self._client().decrypt(CiphertextBlob=base64.b64decode(blob_b64))
        return response["Plaintext"].decode()


def resolve_vault_token(settings: SecAuditSettings) -> str | None:
    if settings.vault_token_file:
        try:
            return Path(settings.vault_token_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise RuntimeError("Unable to read VAULT_TOKEN_FILE.") from exc
    return settings.vault_token


def create_secrets_backend(settings: SecAuditSettings) -> SecretsBackend:
    kind = settings.secrets_backend_effective
    if kind == SecretsBackendKind.FERNET:
        return FernetSecretsBackend(settings.secrets_fernet_key_effective)
    if kind == SecretsBackendKind.VAULT:
        token = resolve_vault_token(settings)
        if not settings.vault_addr or not token:
            raise RuntimeError("Vault secrets backend requires VAULT_ADDR and VAULT_TOKEN (or VAULT_TOKEN_FILE).")
        return VaultTransitSecretsBackend(
            addr=settings.vault_addr,
            token=token,
            mount=settings.vault_transit_mount,
            key=settings.vault_transit_key,
        )
    if kind == SecretsBackendKind.AWS_KMS:
        key_id = settings.aws_kms_key_id
        if not key_id:
            raise RuntimeError("AWS KMS secrets backend requires AWS_KMS_KEY_ID.")
        region = settings.aws_kms_region_effective
        return AwsKmsSecretsBackend(key_id=key_id, region=region)
    raise RuntimeError(f"Unsupported secrets backend: {kind}")


def decrypt_with_fallback(token: str, settings: SecAuditSettings) -> str:
    """Decrypt using envelope prefix; legacy Fernet blobs without prefix stay supported.

    Tries ``secrets_fernet_key_effective`` first, then ``secret_key`` when they differ
    so rotating to a dedicated Fernet key still unlocks older ciphertext.
    """
    if token.startswith(VAULT_PREFIX):
        backend = VaultTransitSecretsBackend(
            addr=settings.vault_addr or "",
            token=resolve_vault_token(settings) or "",
            mount=settings.vault_transit_mount,
            key=settings.vault_transit_key,
        )
        return backend.decrypt(token)
    if token.startswith(AWS_KMS_PREFIX):
        backend = AwsKmsSecretsBackend(
            key_id=settings.aws_kms_key_id or "",
            region=settings.aws_kms_region_effective,
        )
        return backend.decrypt(token)

    primary = settings.secrets_fernet_key_effective
    try:
        return FernetSecretsBackend(primary).decrypt(token)
    except ValueError:
        legacy = settings.secret_key
        if legacy and legacy != primary:
            return FernetSecretsBackend(legacy).decrypt(token)
        raise
