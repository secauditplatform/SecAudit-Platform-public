"""Redis / Sentinel configuration helpers shared by API and workers."""

from __future__ import annotations

from functools import lru_cache
from urllib.parse import urlparse


def parse_redis_db(redis_url: str, *, default: int = 0) -> int:
    path = urlparse(redis_url).path.lstrip("/")
    if path.isdigit():
        return int(path)
    return default


def parse_sentinel_hosts(raw: str) -> list[tuple[str, int]]:
    hosts: list[tuple[str, int]] = []
    for item in raw.split(","):
        entry = item.strip()
        if not entry:
            continue
        if ":" in entry:
            host, port_raw = entry.rsplit(":", 1)
            port = int(port_raw)
        else:
            host, port = entry, 26379
        hosts.append((host, port))
    if not hosts:
        raise ValueError("REDIS_SENTINEL_HOSTS must list at least one sentinel host:port")
    return hosts


def build_sentinel_url(
    *,
    hosts: list[tuple[str, int]],
    db: int,
    password: str | None = None,
) -> str:
    auth = f":{password}@" if password else ""
    return ";".join(f"sentinel://{auth}{host}:{port}/{db}" for host, port in hosts)


def celery_transport_options(
    *,
    master_name: str,
    sentinel_password: str | None = None,
) -> dict:
    options: dict = {"master_name": master_name}
    if sentinel_password:
        options["sentinel_kwargs"] = {"password": sentinel_password}
    return options


@lru_cache
def transport_options_cache_key(master_name: str, sentinel_password: str | None) -> str:
    return f"{master_name}|{sentinel_password or ''}"
