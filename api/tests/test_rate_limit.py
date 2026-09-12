import pytest
from unittest.mock import AsyncMock, patch

from secaudit_core.ssh_fingerprint import (
    fingerprint_from_known_hosts_line,
    normalize_ssh_fingerprint,
)


def test_normalize_ssh_fingerprint_adds_prefix():
    assert normalize_ssh_fingerprint("abc123+/=") == "SHA256:abc123+/"


def test_fingerprint_from_known_hosts_line():
    line = "example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGexamplekeydata"
    # Use a minimal valid-looking base64 blob for ed25519 (32 byte key in openssh format)
    import base64
    import hashlib

    key_inner = b"\x00\x00\x00\x0bssh-ed25519" + b"x" * 32
    key_b64 = base64.b64encode(key_inner).decode()
    line = f"example.com ssh-ed25519 {key_b64}"
    expected = "SHA256:" + base64.b64encode(hashlib.sha256(key_inner).digest()).decode().rstrip("=")
    assert fingerprint_from_known_hosts_line(line) == expected


@pytest.mark.asyncio
async def test_enforce_rate_limit_blocks_after_max():
    from fastapi import HTTPException

    from app.services.rate_limit import enforce_rate_limit

    class _FakeRedis:
        def __init__(self):
            self.values: dict[str, int] = {}

        async def incr(self, key):
            self.values[key] = self.values.get(key, 0) + 1
            return self.values[key]

        async def expire(self, key, ttl):
            return True

        async def aclose(self):
            return None

    fake = _FakeRedis()

    class _Request:
        headers = {}
        client = type("C", (), {"host": "1.2.3.4"})()

    request = _Request()

    with patch("app.services.rate_limit.async_redis", return_value=fake):
        for _ in range(3):
            await enforce_rate_limit(request, scope="test", max_attempts=3, window_seconds=60)
        with pytest.raises(HTTPException) as exc:
            await enforce_rate_limit(request, scope="test", max_attempts=3, window_seconds=60)
        assert exc.value.status_code == 429


@pytest.mark.asyncio
async def test_enforce_rate_limit_fails_closed_on_redis_error():
    from fastapi import HTTPException

    from app.services.rate_limit import enforce_rate_limit

    class _Request:
        headers = {}
        client = type("C", (), {"host": "1.2.3.4"})()

    with patch("app.services.rate_limit.async_redis", side_effect=RuntimeError("redis down")):
        with pytest.raises(HTTPException) as exc:
            await enforce_rate_limit(_Request(), scope="test", max_attempts=3, window_seconds=60)
        assert exc.value.status_code == 503


def test_client_ip_ignores_xff_without_trusted_proxy(monkeypatch):
    from app.core.config import settings
    from app.services.rate_limit import _client_ip

    monkeypatch.setattr(settings, "trusted_proxy_ips", "")

    class _Request:
        headers = {"x-forwarded-for": "9.9.9.9"}
        client = type("C", (), {"host": "1.2.3.4"})()

    assert _client_ip(_Request()) == "1.2.3.4"


def test_client_ip_honors_xff_from_trusted_proxy(monkeypatch):
    from app.core.config import settings
    from app.services.rate_limit import _client_ip

    monkeypatch.setattr(settings, "trusted_proxy_ips", "10.0.0.1")

    class _Request:
        headers = {"x-forwarded-for": "9.9.9.9, 10.0.0.1"}
        client = type("C", (), {"host": "10.0.0.1"})()

    assert _client_ip(_Request()) == "9.9.9.9"


@pytest.mark.asyncio
async def test_enforce_rate_limit_fails_closed_when_redis_errors():
    from fastapi import HTTPException

    from app.services.rate_limit import enforce_rate_limit

    class _Request:
        headers = {}
        client = type("C", (), {"host": "1.2.3.4"})()

    with patch("app.services.rate_limit.async_redis", side_effect=RuntimeError("redis down")):
        with pytest.raises(HTTPException) as exc:
            await enforce_rate_limit(_Request(), scope="test", max_attempts=3, window_seconds=60)
        assert exc.value.status_code == 503


@pytest.mark.asyncio
async def test_enforce_rate_limit_ignores_xff_without_trusted_proxy(monkeypatch):
    from app.core.config import settings
    from app.services.rate_limit import _client_ip

    monkeypatch.setattr(settings, "trusted_proxy_ips", "")

    class _Request:
        headers = {"x-forwarded-for": "9.9.9.9"}
        client = type("C", (), {"host": "1.2.3.4"})()

    assert _client_ip(_Request()) == "1.2.3.4"
