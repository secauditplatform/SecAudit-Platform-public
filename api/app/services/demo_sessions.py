"""Concurrent demo-stand session registry (Redis)."""

from __future__ import annotations

import logging
import time
import uuid

from fastapi import HTTPException, status

from app.core.config import settings
from secaudit_core.redis_client import async_redis

logger = logging.getLogger(__name__)

_SESSIONS_KEY = "secaudit:demo:sessions"


def _idle_ttl(ttl_seconds: int | None = None) -> int:
    return max(60, ttl_seconds or settings.demo_session_idle_seconds)


async def acquire_demo_session(*, ttl_seconds: int | None = None) -> str:
    """Register a new demo session or raise 429 when the stand is full."""
    if not settings.demo_mode:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Demo login is disabled")

    max_sessions = max(1, settings.demo_max_sessions)
    ttl = _idle_ttl(ttl_seconds)
    session_id = str(uuid.uuid4())
    now = int(time.time())
    expires_at = now + ttl

    try:
        client = async_redis(settings.redis_url, settings=settings)
        try:
            await client.zremrangebyscore(_SESSIONS_KEY, "-inf", now)
            active = await client.zcard(_SESSIONS_KEY)
            if active >= max_sessions:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=(
                        f"Demo stand is at capacity ({max_sessions} concurrent sessions). "
                        "Try again later."
                    ),
                )
            await client.zadd(_SESSIONS_KEY, {session_id: expires_at})
            await client.expire(_SESSIONS_KEY, ttl)
            return session_id
        finally:
            await client.aclose()
    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to acquire demo session slot")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Demo session registry unavailable",
        ) from None


async def release_demo_session(session_id: str | None) -> None:
    if not session_id or not settings.demo_mode:
        return
    try:
        client = async_redis(settings.redis_url, settings=settings)
        try:
            await client.zrem(_SESSIONS_KEY, session_id)
        finally:
            await client.aclose()
    except Exception:
        logger.warning("Failed to release demo session %s", session_id, exc_info=True)


async def touch_demo_session(session_id: str | None, *, ttl_seconds: int | None = None) -> None:
    """Extend an existing demo session TTL on activity, or reject if idle-expired."""
    if not session_id or not settings.demo_mode:
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
                    detail="Demo session expired due to inactivity",
                )
            await client.zadd(_SESSIONS_KEY, {session_id: expires_at})
            await client.expire(_SESSIONS_KEY, ttl)
        finally:
            await client.aclose()
    except HTTPException:
        raise
    except Exception:
        logger.warning("Failed to renew demo session %s", session_id, exc_info=True)
