"""Local-auth idle session registry for the main platform (not demo)."""

from __future__ import annotations

import logging
import time
import uuid

from fastapi import HTTPException, status

from app.core.config import settings
from secaudit_core.redis_client import async_redis

logger = logging.getLogger(__name__)

_SESSIONS_KEY = "secaudit:auth:sessions"


def auth_idle_enabled() -> bool:
    return (
        not settings.demo_mode
        and settings.auth_enabled
        and settings.local_auth_enabled
        and settings.auth_idle_timeout_seconds > 0
    )


def _idle_ttl(ttl_seconds: int | None = None) -> int:
    return max(60, ttl_seconds or settings.auth_idle_timeout_seconds)


async def acquire_auth_session(*, ttl_seconds: int | None = None) -> str:
    """Register a new local-auth session tracked for idle timeout."""
    if not auth_idle_enabled():
        return str(uuid.uuid4())

    ttl = _idle_ttl(ttl_seconds)
    session_id = str(uuid.uuid4())
    expires_at = int(time.time()) + ttl

    try:
        client = async_redis(settings.redis_url, settings=settings)
        try:
            await client.zadd(_SESSIONS_KEY, {session_id: expires_at})
            await client.expire(_SESSIONS_KEY, ttl)
            return session_id
        finally:
            await client.aclose()
    except Exception:
        logger.exception("Failed to acquire auth idle session")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Auth session registry unavailable",
        ) from None


async def release_auth_session(session_id: str | None) -> None:
    if not session_id or settings.demo_mode:
        return
    try:
        client = async_redis(settings.redis_url, settings=settings)
        try:
            await client.zrem(_SESSIONS_KEY, session_id)
        finally:
            await client.aclose()
    except Exception:
        logger.warning("Failed to release auth session %s", session_id, exc_info=True)


_REVOKED_KEY_PREFIX = "secaudit:auth:revoked:"


async def revoke_auth_token(jti: str | None, *, ttl_seconds: int) -> None:
    """Blacklist a local-auth JWT ``jti`` until the token would have expired."""
    if not jti or ttl_seconds <= 0:
        return
    try:
        client = async_redis(settings.redis_url, settings=settings)
        try:
            await client.setex(f"{_REVOKED_KEY_PREFIX}{jti}", max(60, ttl_seconds), "1")
        finally:
            await client.aclose()
    except Exception:
        logger.warning("Failed to revoke auth token %s", jti, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Auth token revocation unavailable",
        ) from None


async def is_auth_token_revoked(jti: str | None) -> bool:
    if not jti:
        return False
    try:
        client = async_redis(settings.redis_url, settings=settings)
        try:
            return bool(await client.exists(f"{_REVOKED_KEY_PREFIX}{jti}"))
        finally:
            await client.aclose()
    except Exception:
        logger.warning("Failed to check revoked auth token %s", jti, exc_info=True)
        # Fail closed for revocation checks when Redis is down.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Auth token registry unavailable",
        ) from None


async def touch_auth_session(session_id: str | None, *, ttl_seconds: int | None = None) -> None:
    """Extend idle TTL on activity, or reject when the session timed out."""
    if not session_id or not auth_idle_enabled():
        return

    ttl = _idle_ttl(ttl_seconds)
    now = int(time.time())
    expires_at = now + ttl
    try:
        client = async_redis(settings.redis_url, settings=settings)
        try:
            await client.zremrangebyscore(_SESSIONS_KEY, "-inf", now)
            score = await client.zscore(_SESSIONS_KEY, session_id)
            if score is None or float(score) < now:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Session expired due to inactivity",
                )
            await client.zadd(_SESSIONS_KEY, {session_id: expires_at})
            await client.expire(_SESSIONS_KEY, ttl)
        finally:
            await client.aclose()
    except HTTPException:
        raise
    except Exception:
        logger.warning("Failed to renew auth session %s", session_id, exc_info=True)
