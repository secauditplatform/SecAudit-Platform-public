"""Cross-JobRun Redis lock so two workers do not share one host session."""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable
from typing import TYPE_CHECKING

from secaudit_core.beat_lock import release_beat_lock
from secaudit_core.redis_client import sync_redis

if TYPE_CHECKING:
    from redis import Redis


def host_lock_key(host_id: int) -> str:
    return f"host_lock:{int(host_id)}"


def acquire_host_lock(
    redis_url: str,
    host_id: int,
    *,
    ttl_seconds: int = 1800,
    wait_seconds: float = 30.0,
    poll_interval: float = 0.5,
    should_abort: Callable[[], bool] | None = None,
) -> tuple[Redis | None, str | None]:
    """Acquire ``host_lock:{host_id}``, queuing up to ``wait_seconds`` for a free slot."""
    key = host_lock_key(host_id)
    client = sync_redis(redis_url, decode_responses=True)
    token = str(uuid.uuid4())
    ttl = max(1, int(ttl_seconds))
    deadline = time.monotonic() + max(0.0, float(wait_seconds))
    while True:
        if client.set(key, token, nx=True, ex=ttl):
            return client, token
        if should_abort and should_abort():
            client.close()
            return None, None
        if time.monotonic() >= deadline:
            client.close()
            return None, None
        time.sleep(max(0.05, float(poll_interval)))


def release_host_lock(
    client: Redis | None,
    host_id: int,
    token: str | None,
) -> None:
    release_beat_lock(client, host_lock_key(host_id), token)
