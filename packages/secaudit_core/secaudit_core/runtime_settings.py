"""Redis overrides for a few ops knobs editable from the admin System health tab."""

from __future__ import annotations

from secaudit_core.redis_client import sync_redis

RETENTION_DAYS_KEY = "secaudit:settings:job_run_retention_days"


def get_job_run_retention_days(redis_url: str, *, env_default: int) -> int:
    client = sync_redis(redis_url, decode_responses=True)
    try:
        raw = client.get(RETENTION_DAYS_KEY)
    finally:
        client.close()
    if raw is None or raw == "":
        return max(0, int(env_default))
    try:
        return max(0, int(raw))
    except (TypeError, ValueError):
        return max(0, int(env_default))


def set_job_run_retention_days(redis_url: str, days: int) -> int:
    value = max(0, int(days))
    client = sync_redis(redis_url, decode_responses=True)
    try:
        client.set(RETENTION_DAYS_KEY, str(value))
    finally:
        client.close()
    return value
