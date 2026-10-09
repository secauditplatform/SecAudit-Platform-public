"""Scoped service-account API keys for CI/CD."""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import ApiKey

API_KEY_PREFIX_TOKEN = "sa_"
ALLOWED_SCOPES = frozenset({"jobs:run", "reports:read", "inventory:scan"})


def normalize_scopes(scopes: list[str] | None) -> list[str]:
    if not scopes:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="At least one scope is required")
    cleaned = sorted({str(s).strip() for s in scopes if str(s).strip()})
    unknown = [s for s in cleaned if s not in ALLOWED_SCOPES]
    if unknown:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown scopes: {', '.join(unknown)}",
        )
    if not cleaned:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="At least one scope is required")
    return cleaned


def hash_api_key_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


def generate_api_key_material() -> tuple[str, str, str]:
    """Return (prefix, full_token, hash). Token format: sa_<prefix>_<secret>."""
    prefix = secrets.token_hex(4)
    secret = secrets.token_urlsafe(32)
    token = f"{API_KEY_PREFIX_TOKEN}{prefix}_{secret}"
    return prefix, token, hash_api_key_secret(token)


def parse_api_key_token(token: str) -> tuple[str, str] | None:
    """Return (prefix, full_token) if token looks like an API key."""
    if not token.startswith(API_KEY_PREFIX_TOKEN):
        return None
    rest = token[len(API_KEY_PREFIX_TOKEN) :]
    if "_" not in rest:
        return None
    prefix, _secret = rest.split("_", 1)
    if len(prefix) != 8 or not _secret:
        return None
    return prefix, token


def is_api_key_usable(row: ApiKey, *, now: datetime | None = None) -> bool:
    now = now or datetime.now(UTC)
    if not row.is_active or row.revoked_at is not None:
        return False
    if row.expires_at is not None and row.expires_at <= now:
        return False
    return True


async def resolve_api_key_user(db: AsyncSession, token: str):
    """Validate Bearer API key and return AuthUser-compatible fields + row."""
    from app.core.auth import AuthUser

    parsed = parse_api_key_token(token)
    if not parsed:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
    prefix, full = parsed
    result = await db.execute(select(ApiKey).where(ApiKey.key_prefix == prefix))
    row = result.scalar_one_or_none()
    if not row or not is_api_key_usable(row):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
    if not secrets.compare_digest(row.key_hash, hash_api_key_secret(full)):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")

    row.last_used_at = datetime.now(UTC)
    await db.commit()

    scopes = list(row.scopes or [])
    return AuthUser(
        sub=f"api_key:{row.id}",
        username=row.name,
        roles=[],
        auth_mode="api_key",
        local_source=None,
        scopes=scopes,
    ), row


async def get_api_key_or_404(db: AsyncSession, key_id: int) -> ApiKey:
    row = await db.get(ApiKey, key_id)
    if not row:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")
    return row
