"""TOTP multi-factor authentication for local (database) users."""

from __future__ import annotations

import logging
import secrets as secrets_mod
from urllib.parse import quote

import pyotp
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.passwords import hash_password, verify_password
from app.core.secrets import decrypt_secret, encrypt_secret
from app.models import User
from secaudit_core.redis_client import async_redis

logger = logging.getLogger(__name__)

TOTP_DIGITS = 6
TOTP_INTERVAL_SECONDS = 30
TOTP_VALID_WINDOW = 1
DEFAULT_ISSUER = "SecAudit"
# Unambiguous alphabet: no 0/O/1/I so codes stay readable when written down.
_RECOVERY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_RECOVERY_GROUP_LEN = 5
_RECOVERY_GROUPS = 2
_SETUP_KEY_PREFIX = "secaudit:mfa:setup:"


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def encrypt_totp_secret(secret: str) -> str:
    return encrypt_secret(secret, settings)


def decrypt_totp_secret(encrypted: str) -> str:
    return decrypt_secret(encrypted, settings)


def verify_totp(secret: str, code: str) -> bool:
    normalized = (code or "").strip().replace(" ", "")
    if not secret or not normalized.isdigit():
        return False
    totp = pyotp.TOTP(secret, digits=TOTP_DIGITS, interval=TOTP_INTERVAL_SECONDS)
    try:
        return bool(totp.verify(normalized, valid_window=TOTP_VALID_WINDOW))
    except Exception:
        return False


def build_otpauth_uri(username: str, secret: str, issuer: str = DEFAULT_ISSUER) -> str:
    label = quote(f"{issuer}:{username}", safe="")
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer, safe='')}"
        f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_INTERVAL_SECONDS}"
    )


def generate_recovery_codes(n: int = 8) -> list[str]:
    codes: list[str] = []
    for _ in range(max(1, n)):
        groups = [
            "".join(secrets_mod.choice(_RECOVERY_ALPHABET) for _ in range(_RECOVERY_GROUP_LEN))
            for _ in range(_RECOVERY_GROUPS)
        ]
        codes.append("-".join(groups))
    return codes


def normalize_recovery_code(code: str) -> str:
    return (code or "").strip().upper().replace("-", "").replace(" ", "")


def hash_recovery_codes(codes: list[str]) -> list[str]:
    return [hash_password(normalize_recovery_code(code)) for code in codes]


def verify_and_consume_recovery_code(user: User, code: str, db: AsyncSession) -> bool:
    """Match ``code`` against the stored hashes and drop the hash that matched."""
    normalized = normalize_recovery_code(code)
    if not normalized:
        return False
    hashes = list(user.mfa_recovery_codes_json or [])
    for index, stored in enumerate(hashes):
        if not isinstance(stored, str):
            continue
        if verify_password(normalized, stored):
            remaining = hashes[:index] + hashes[index + 1 :]
            # JSON columns need a new list object to be picked up as dirty.
            user.mfa_recovery_codes_json = remaining
            db.add(user)
            return True
    return False


def verify_mfa_code(user: User, code: str, db: AsyncSession) -> bool:
    """Accept either a live TOTP code or one unused recovery code."""
    encrypted = user.totp_secret_encrypted
    if encrypted:
        try:
            if verify_totp(decrypt_totp_secret(encrypted), code):
                return True
        except Exception:
            logger.warning("Unable to decrypt TOTP secret for user %s", user.username, exc_info=True)
    return verify_and_consume_recovery_code(user, code, db)


def clear_mfa(user: User) -> None:
    user.mfa_enabled = False
    user.totp_secret_encrypted = None
    user.mfa_recovery_codes_json = None


def _setup_key(username: str) -> str:
    return f"{_SETUP_KEY_PREFIX}{username}"


async def store_pending_secret(username: str, secret: str) -> None:
    """Hold the unconfirmed enrollment secret (encrypted) in Redis, never in the DB."""
    ttl = max(60, settings.local_auth_mfa_setup_ttl_seconds)
    try:
        client = async_redis(settings.redis_url, settings=settings)
        try:
            await client.setex(_setup_key(username), ttl, encrypt_totp_secret(secret))
        finally:
            await client.aclose()
    except Exception as exc:
        logger.warning("Failed to store pending MFA secret for %s", username, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MFA enrollment store unavailable",
        ) from exc


async def load_pending_secret(username: str) -> str | None:
    try:
        client = async_redis(settings.redis_url, settings=settings)
        try:
            raw = await client.get(_setup_key(username))
        finally:
            await client.aclose()
    except Exception as exc:
        logger.warning("Failed to load pending MFA secret for %s", username, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MFA enrollment store unavailable",
        ) from exc
    if not raw:
        return None
    try:
        return decrypt_totp_secret(raw)
    except Exception:
        logger.warning("Discarding undecryptable pending MFA secret for %s", username, exc_info=True)
        return None


async def discard_pending_secret(username: str) -> None:
    try:
        client = async_redis(settings.redis_url, settings=settings)
        try:
            await client.delete(_setup_key(username))
        finally:
            await client.aclose()
    except Exception:
        logger.warning("Failed to discard pending MFA secret for %s", username, exc_info=True)
