"""Ed25519 signing for Evidence Pack manifest.json."""

from __future__ import annotations

import base64
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

DEFAULT_KEY_PATH = "/data/reports/evidence_ed25519.pem"


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def load_or_create_private_key(key_path: str | Path | None = None) -> Ed25519PrivateKey:
    path = Path(key_path or DEFAULT_KEY_PATH)
    if path.is_file():
        data = path.read_bytes()
        return serialization.load_pem_private_key(data, password=None)
    _ensure_parent(path)
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return key


def public_key_pem(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def sign_manifest(manifest_bytes: bytes, *, key_path: str | Path | None = None) -> tuple[bytes, bytes]:
    """Return (signature_raw, public_pem)."""
    key = load_or_create_private_key(key_path)
    return key.sign(manifest_bytes), public_key_pem(key)


def signature_b64(signature: bytes) -> str:
    return base64.b64encode(signature).decode("ascii")


def verify_manifest(
    manifest_bytes: bytes,
    signature: bytes,
    public_pem: bytes,
) -> bool:
    public = serialization.load_pem_public_key(public_pem)
    if not isinstance(public, Ed25519PublicKey):
        return False
    try:
        public.verify(signature, manifest_bytes)
        return True
    except Exception:
        return False
