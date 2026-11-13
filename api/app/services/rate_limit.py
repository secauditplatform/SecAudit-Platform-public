"""Redis-backed rate limiting for sensitive API endpoints."""

from __future__ import annotations

import logging

from fastapi import HTTPException, Request, status

from app.core.client_ip import client_ip
from app.core.config import settings
from secaudit_core.redis_client import async_redis

logger = logging.getLogger(__name__)


async def enforce_rate_limit(
    request: Request,
    *,
    scope: str,
    max_attempts: int,
    window_seconds: int,
) -> None:
    if max_attempts <= 0 or window_seconds <= 0:
        return

    ip = client_ip(request)
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
        # Auth scopes must fail closed in production when Redis is down.
        auth_scopes = {"auth_local", "auth_mfa", "auth_demo", "auth_refresh", "login", "mfa"}
        if settings.app_env == "production" and scope in auth_scopes:
            logger.error(
                "Rate limit check failed for auth scope %s; rejecting request (fail-closed)",
                scope,
                exc_info=True,
            )
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Authentication temporarily unavailable. Try again later.",
            ) from None
        logger.warning(
            "Rate limit check failed for scope %s; allowing request", scope, exc_info=True
        )
