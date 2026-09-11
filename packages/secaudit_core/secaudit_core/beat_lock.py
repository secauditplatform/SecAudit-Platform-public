"""Distributed lock for Celery Beat scheduled tasks."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

import redis

from secaudit_core.redis_client import sync_redis

if TYPE_CHECKING:
    from redis import Redis

_RELEASE_SCRIPT = """
if redis.call("get", KEYS[1]) == ARGV[1] then
    return redis.call("del", KEYS[1])
else
    return 0
end
"""


def acquire_beat_lock(
    redis_url: str,
    lock_key: str,
    *,
    ttl_seconds: int = 55,
) -> tuple[Redis | None, str | None]:
    """Try to acquire a beat schedule lock. Returns (client, token) or (None, None)."""
    client = sync_redis(redis_url, decode_responses=True)
    token = str(uuid.uuid4())
    if client.set(lock_key, token, nx=True, ex=ttl_seconds):
        return client, token
    client.close()
    return None, None


def release_beat_lock(
    client: Redis | None,
    lock_key: str,
    token: str | None,
) -> None:
    """Release the lock only if this holder still owns it."""
    if client is None or token is None:
        return
    try:
        client.eval(_RELEASE_SCRIPT, 1, lock_key, token)
    finally:
        client.close()
