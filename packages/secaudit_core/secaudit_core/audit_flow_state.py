"""Redis cancel flags and live progress for AuditFlow scans."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import redis

from secaudit_core.redis_client import sync_redis

_TTL = 86400


def _client(redis_url: str) -> redis.Redis:
    return sync_redis(redis_url, decode_responses=True)


def request_audit_flow_cancel(redis_url: str, run_id: int) -> None:
    client = _client(redis_url)
    client.set(f"audit_flow:{run_id}:cancel", "1", ex=_TTL)
    pid = client.get(f"audit_flow:{run_id}:pid")
    if pid:
        try:
            import os
            import signal

            os.kill(int(pid), signal.SIGTERM)
        except (ProcessLookupError, ValueError, OSError):
            pass


def is_audit_flow_cancelled(redis_url: str, run_id: int) -> bool:
    return _client(redis_url).get(f"audit_flow:{run_id}:cancel") == "1"


def set_audit_flow_pid(redis_url: str, run_id: int, pid: int) -> None:
    _client(redis_url).set(f"audit_flow:{run_id}:pid", str(pid), ex=_TTL)


def append_audit_flow_log(redis_url: str, run_id: int, message: str, *, level: str = "info") -> None:
    payload = json.dumps(
        {
            "audit_flow_run_id": run_id,
            "level": level,
            "message": message,
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )
    client = _client(redis_url)
    client.publish(f"audit_flow_run:{run_id}", payload)
    client.lpush(f"audit_flow_run_logs:{run_id}", payload)
    client.expire(f"audit_flow_run_logs:{run_id}", _TTL)


def set_audit_flow_progress(
    redis_url: str,
    run_id: int,
    *,
    phase: str,
    target: str | None = None,
    address: str | None = None,
) -> None:
    payload = {"phase": phase, "target": target, "address": address}
    _client(redis_url).set(f"audit_flow:{run_id}:progress", json.dumps(payload), ex=_TTL)


def get_audit_flow_progress(redis_url: str, run_id: int) -> dict | None:
    raw = _client(redis_url).get(f"audit_flow:{run_id}:progress")
    if not raw:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def clear_audit_flow_state(redis_url: str, run_id: int) -> None:
    client = _client(redis_url)
    client.delete(f"audit_flow:{run_id}:cancel", f"audit_flow:{run_id}:pid", f"audit_flow:{run_id}:progress")
