"""Tests for Redis Sentinel configuration and client factory."""

from unittest.mock import MagicMock, patch

import pytest

from secaudit_core.redis_config import (
    build_sentinel_url,
    celery_transport_options,
    parse_redis_db,
    parse_sentinel_hosts,
)
from secaudit_core.settings import SecAuditSettings


def test_parse_sentinel_hosts():
    hosts = parse_sentinel_hosts("sentinel1:26379,sentinel2:26379,sentinel3")
    assert hosts == [("sentinel1", 26379), ("sentinel2", 26379), ("sentinel3", 26379)]


def test_parse_redis_db_from_url():
    assert parse_redis_db("redis://localhost:6379/2") == 2
    assert parse_redis_db("redis://localhost:6379", default=0) == 0


def test_build_sentinel_url():
    url = build_sentinel_url(
        hosts=[("s1", 26379), ("s2", 26379)],
        db=0,
        password="secret",
    )
    assert url.startswith("sentinel://:secret@s1:26379/0;")
    assert url.endswith("sentinel://:secret@s2:26379/0")


def test_settings_sentinel_enabled():
    settings = SecAuditSettings(
        redis_sentinel_hosts="s1:26379",
        celery_broker_url="redis://ignored/0",
        celery_result_backend="redis://ignored/1",
    )
    assert settings.redis_sentinel_enabled is True
    assert "sentinel://" in settings.celery_broker_url_effective
    assert settings.celery_transport_options()["master_name"] == "secaudit-master"


def test_sync_redis_uses_sentinel_when_configured():
    from secaudit_core.redis_client import sync_redis

    settings = SecAuditSettings(redis_sentinel_hosts="s1:26379")
    mock_master = MagicMock()
    mock_sentinel_cls = MagicMock()
    mock_sentinel_cls.return_value.master_for.return_value = mock_master

    with patch("redis.sentinel.Sentinel", mock_sentinel_cls):
        client = sync_redis("redis://logical/0", settings=settings)

    assert client is mock_master
    mock_sentinel_cls.return_value.master_for.assert_called_once()


def test_celery_transport_options_password():
    opts = celery_transport_options(master_name="mymaster", sentinel_password="s3cr3t")
    assert opts["master_name"] == "mymaster"
    assert opts["sentinel_kwargs"]["password"] == "s3cr3t"
