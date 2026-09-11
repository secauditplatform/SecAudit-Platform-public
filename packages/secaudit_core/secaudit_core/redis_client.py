"""Central Redis client factory with optional Sentinel support."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

import redis
import redis.asyncio as aioredis

from secaudit_core.redis_config import parse_redis_db, parse_sentinel_hosts

if TYPE_CHECKING:
    from secaudit_core.settings import SecAuditSettings


def _load_settings() -> SecAuditSettings:
    from secaudit_core.settings import SecAuditSettings

    return SecAuditSettings()


def _socket_kwargs(settings: SecAuditSettings) -> dict[str, float]:
    return {
        "socket_connect_timeout": settings.redis_socket_connect_timeout_seconds,
        "socket_timeout": settings.redis_socket_timeout_seconds,
    }


def _sentinel_kwargs(settings: SecAuditSettings) -> dict[str, Any]:
    kwargs: dict[str, Any] = {"decode_responses": True, **_socket_kwargs(settings)}
    if settings.redis_sentinel_password:
        kwargs["password"] = settings.redis_sentinel_password
    return kwargs


def _master_kwargs(settings: SecAuditSettings, *, db: int, **overrides: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "db": db,
        "decode_responses": True,
        **_socket_kwargs(settings),
    }
    if settings.redis_password:
        kwargs["password"] = settings.redis_password
    if settings.redis_ssl:
        kwargs["ssl"] = True
        kwargs["ssl_cert_reqs"] = settings.redis_ssl_cert_reqs
    kwargs.update(overrides)
    return kwargs


def _standalone_kwargs(settings: SecAuditSettings, **overrides: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = {"decode_responses": True, **_socket_kwargs(settings)}
    kwargs.update(overrides)
    return kwargs


def sync_redis(redis_url: str, settings: SecAuditSettings | None = None, **overrides: Any) -> redis.Redis:
    """Return a synchronous Redis client for the given logical URL (db is taken from the path)."""
    settings = settings or _load_settings()
    if settings.redis_sentinel_enabled:
        from redis.sentinel import Sentinel

        db = parse_redis_db(redis_url, default=settings.redis_db)
        sentinel = Sentinel(
            parse_sentinel_hosts(settings.redis_sentinel_hosts or ""),
            sentinel_kwargs=_sentinel_kwargs(settings),
            **_socket_kwargs(settings),
        )
        return sentinel.master_for(
            settings.redis_sentinel_master_name,
            **_master_kwargs(settings, db=db, **overrides),
        )
    return redis.from_url(redis_url, **_standalone_kwargs(settings, **overrides))


def async_redis(redis_url: str, settings: SecAuditSettings | None = None, **overrides: Any) -> aioredis.Redis:
    """Return an asyncio Redis client for the given logical URL."""
    settings = settings or _load_settings()
    if settings.redis_sentinel_enabled:
        from redis.asyncio.sentinel import Sentinel as AsyncSentinel

        db = parse_redis_db(redis_url, default=settings.redis_db)
        sentinel = AsyncSentinel(
            parse_sentinel_hosts(settings.redis_sentinel_hosts or ""),
            sentinel_kwargs=_sentinel_kwargs(settings),
            **_socket_kwargs(settings),
        )
        return sentinel.master_for(
            settings.redis_sentinel_master_name,
            **_master_kwargs(settings, db=db, **overrides),
        )
    return aioredis.from_url(redis_url, **_standalone_kwargs(settings, **overrides))


def redis_url_host(redis_url: str) -> str:
    return urlparse(redis_url).hostname or "localhost"
