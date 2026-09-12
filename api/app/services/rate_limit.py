"""Redis-backed rate limiting for sensitive API endpoints."""

from __future__ import annotations

import logging

from fastapi import HTTPException, Request, status

from app.core.config import settings
from secaudit_core.redis_client import async_redis

logger = logging.getLogger(__name__)


def _client_ip(request: Request) -> str:
    """Return client IP; honor X-Forwarded-For only behind a configured trusted proxy."""
    peer = request.client.host if request.client else None
    trusted = {
        item.strip()
        for item in (settings.trusted_proxy_ips or "").split(",")
        if item.strip()
    }
    if peer and peer in trusted:
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            candidate = forwarded.split(",")[0].strip()
            if candidate:
                return candidate
    if peer:
        return peer
    return "unknown"


async def enforce_rate_limit(
    request: Request,
    *,
    scope: str,
    max_attempts: int,
    window_seconds: int,
) -> None:
    if max_attempts <= 0 or window_seconds <= 0:
        return

    ip = _client_ip(request)
    key = f"secaudit:ratelimit:{scope}:{ip}"

    try:
        client = async_redis(settings.redis_url, settings=settings)
        try:
            count = await client.incr(key)
            if count == 1:
                await client.expire(key, window_seconds)
            if count > max_attempts:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many requests. Try again later.",
                )
        finally:
            await client.aclose()
    except HTTPException:
        raise
    except Exception:
        logger.warning(
            "Rate limit check failed for scope %s; rejecting request (fail-closed)",
            scope,
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Rate limiter unavailable. Try again later.",
        ) from None
