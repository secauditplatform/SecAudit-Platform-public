"""Persist and read scheduled profiles catalog sync status in Redis."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

import redis

from secaudit_core.redis_client import sync_redis

CATALOG_SYNC_STATUS_KEY = "secaudit:profiles:catalog_sync:last_run"
CATALOG_SYNC_STATUS_TTL_SECONDS = 30 * 24 * 3600


def record_catalog_sync_status(redis_url: str, payload: dict[str, Any]) -> None:
    body = {
        **payload,
        "finished_at": datetime.now(UTC).isoformat(),
    }
    client = sync_redis(redis_url, decode_responses=True)
    try:
        client.set(
            CATALOG_SYNC_STATUS_KEY,
            json.dumps(body, ensure_ascii=False),
            ex=CATALOG_SYNC_STATUS_TTL_SECONDS,
        )
    finally:
        client.close()


def load_catalog_sync_status(redis_url: str) -> dict[str, Any] | None:
    client = sync_redis(redis_url, decode_responses=True)
    try:
        raw = client.get(CATALOG_SYNC_STATUS_KEY)
        if not raw:
            return None
        data = json.loads(raw)
        return data if isinstance(data, dict) else None
    finally:
        client.close()
