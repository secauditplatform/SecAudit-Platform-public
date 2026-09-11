"""Redis-backed inventory scan process tracking (cancel flag + PID)."""

from __future__ import annotations

import redis

from secaudit_core.redis_client import sync_redis

_CANCEL_TTL_SECONDS = 86400


def _client(redis_url: str) -> redis.Redis:
    return sync_redis(redis_url, decode_responses=True)


def _cancel_key(scan_id: int) -> str:
    return f"inventory_scan:{scan_id}:cancel"


def _pid_key(scan_id: int) -> str:
    return f"inventory_scan:{scan_id}:pid"


def request_scan_cancel(redis_url: str, scan_id: int) -> None:
    """Set cancel flag; worker checks this and terminates nmap."""
    client = _client(redis_url)
    client.set(_cancel_key(scan_id), "1", ex=_CANCEL_TTL_SECONDS)
    pid = client.get(_pid_key(scan_id))
    if pid:
        try:
            import os
            import signal

            os.kill(int(pid), signal.SIGTERM)
        except (ProcessLookupError, ValueError, OSError):
            pass


def is_scan_cancelled(redis_url: str, scan_id: int) -> bool:
    return _client(redis_url).get(_cancel_key(scan_id)) == "1"


def set_scan_pid(redis_url: str, scan_id: int, pid: int) -> None:
    client = _client(redis_url)
    client.set(_pid_key(scan_id), str(pid), ex=_CANCEL_TTL_SECONDS)


def clear_scan_pid(redis_url: str, scan_id: int) -> None:
    _client(redis_url).delete(_pid_key(scan_id))


def clear_scan_state(redis_url: str, scan_id: int) -> None:
    client = _client(redis_url)
    client.delete(_cancel_key(scan_id), _pid_key(scan_id))
