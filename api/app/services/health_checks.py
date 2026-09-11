"""Dependency health probes for readiness checks."""

from __future__ import annotations

import asyncio
import logging
import time
from threading import Lock

from sqlalchemy import text

from app.core.config import settings
from app.core.database import async_session
from app.schemas import ComponentHealth
from secaudit_core.celery_observability import worker_heartbeat_age_seconds
from secaudit_core.celery_redis import create_celery_app
from secaudit_core.redis_client import async_redis

logger = logging.getLogger(__name__)

_cache_lock = Lock()
_cached_components: dict[str, ComponentHealth] | None = None
_cached_at: float = 0.0


def _redact_detail(detail: str | None) -> str | None:
    if not settings.readiness_redact_details:
        return detail
    if not detail:
        return None
    # Keep coarse status hints; drop raw exception / connection strings.
    lowered = detail.lower()
    if "stale" in lowered or "heartbeat" in lowered:
        return "worker heartbeat unhealthy"
    if "no celery workers" in lowered:
        return "no workers available"
    if "worker" in lowered and "ok" in lowered:
        return "workers healthy"
    return "dependency unavailable"


def _safe_error(exc: BaseException) -> ComponentHealth:
    logger.warning("Readiness probe failed: %s", exc)
    return ComponentHealth(status="error", detail=_redact_detail(str(exc)))


async def check_postgres() -> ComponentHealth:
    try:
        async with async_session() as session:
            await session.execute(text("SELECT 1"))
        return ComponentHealth(status="ok")
    except Exception as exc:
        return _safe_error(exc)


async def check_redis() -> ComponentHealth:
    try:
        client = async_redis(settings.redis_url, settings=settings)
        try:
            await client.ping()
        finally:
            await client.aclose()
        return ComponentHealth(status="ok")
    except Exception as exc:
        return _safe_error(exc)


async def check_celery_broker() -> ComponentHealth:
    try:
        broker_url = (
            settings.celery_broker_url_effective
            if settings.redis_sentinel_enabled
            else settings.celery_broker_url
        )
        client = async_redis(broker_url, settings=settings)
        try:
            await client.ping()
        finally:
            await client.aclose()
        return ComponentHealth(status="ok")
    except Exception as exc:
        return _safe_error(exc)


def _check_celery_workers_sync() -> ComponentHealth:
    try:
        app = create_celery_app("secaudit-health", settings)
        inspector = app.control.inspect(timeout=2.0)
        ping = inspector.ping()
        if not ping:
            return ComponentHealth(
                status="error",
                detail=_redact_detail("No Celery workers responded to ping"),
            )
        worker_count = len(ping)

        heartbeat_age = worker_heartbeat_age_seconds(settings.redis_url)
        if heartbeat_age is None:
            return ComponentHealth(
                status="error",
                detail=_redact_detail(
                    f"{worker_count} worker(s) ping ok, but heartbeat timestamp missing"
                ),
            )
        if heartbeat_age > settings.worker_heartbeat_max_age_seconds:
            return ComponentHealth(
                status="error",
                detail=_redact_detail(
                    f"{worker_count} worker(s) ping ok, but heartbeat stale "
                    f"({int(heartbeat_age)}s > {settings.worker_heartbeat_max_age_seconds}s)"
                ),
            )
        return ComponentHealth(
            status="ok",
            detail=_redact_detail(
                f"{worker_count} worker(s), heartbeat {int(heartbeat_age)}s ago"
            ),
        )
    except Exception as exc:
        return _safe_error(exc)


async def check_celery_workers() -> ComponentHealth:
    return await asyncio.to_thread(_check_celery_workers_sync)


async def gather_readiness_components(*, use_cache: bool = True) -> dict[str, ComponentHealth]:
    global _cached_components, _cached_at
    cache_ttl = max(0.0, float(settings.readiness_cache_seconds))
    if use_cache and cache_ttl > 0:
        with _cache_lock:
            if _cached_components is not None and (time.monotonic() - _cached_at) < cache_ttl:
                return dict(_cached_components)

    components = {
        "postgres": await check_postgres(),
        "redis": await check_redis(),
        "celery_broker": await check_celery_broker(),
        "celery_workers": await check_celery_workers(),
    }
    if use_cache and cache_ttl > 0:
        with _cache_lock:
            _cached_components = dict(components)
            _cached_at = time.monotonic()
    return components
