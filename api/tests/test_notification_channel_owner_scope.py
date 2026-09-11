"""Notification channel object RBAC and delivery owner scope."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from app.api.v1.routers import notifications as notifications_router
from app.core.auth import AuthUser
from app.models import NotificationChannel, UserRole
from app.services import object_rbac as object_rbac_service
from secaudit_core.enums import JobStatus, NotificationChannelType, NotificationEventType
from secaudit_core.models import NotificationChannel as CoreNotificationChannel
from secaudit_core.notifications import (
    _channel_owner_matches,
    build_run_notification_payload,
    deliver_notifications,
)


def _channel(**kwargs) -> CoreNotificationChannel:
    defaults = {
        "id": 1,
        "name": "ops",
        "channel_type": NotificationChannelType.WEBHOOK,
        "is_active": True,
        "events": [NotificationEventType.RUN_FAILED.value],
    }
    defaults.update(kwargs)
    return CoreNotificationChannel(**defaults)


def test_channel_owner_matches_run_notification():
    alice_channel = _channel(owner_sub="local:alice")
    platform_channel = _channel(id=2, name="platform", owner_sub=None)
    payload = build_run_notification_payload(
        trigger_events=[NotificationEventType.RUN_FAILED.value],
        run_kind="job",
        run_id=1,
        job_id=1,
        job_name="Audit",
        status=JobStatus.FAILED.value,
        owner_sub="local:alice",
    )
    assert _channel_owner_matches(alice_channel, payload) is True
    assert _channel_owner_matches(platform_channel, payload) is True
    bob_channel = _channel(id=3, name="bob", owner_sub="local:bob")
    assert _channel_owner_matches(bob_channel, payload) is False


def test_channel_owner_matches_platform_payload():
    platform_channel = _channel(owner_sub=None)
    engineer_channel = _channel(owner_sub="local:alice")
    payload = {"payload_type": "platform", "trigger_events": ["worker_heartbeat_stale"]}
    assert _channel_owner_matches(platform_channel, payload) is True
    assert _channel_owner_matches(engineer_channel, payload) is False


def test_deliver_notifications_skips_foreign_engineer_channel(monkeypatch):
    payload = build_run_notification_payload(
        trigger_events=[NotificationEventType.RUN_FAILED.value],
        run_kind="job",
        run_id=42,
        job_id=7,
        job_name="Linux audit",
        status=JobStatus.FAILED.value,
        owner_sub="local:alice",
    )
    alice_channel = _channel(id=1, name="alice-hook", owner_sub="local:alice", encrypted_secret=None, config_json={"webhook_url": "https://a.test/hook"})
    bob_channel = _channel(id=2, name="bob-hook", owner_sub="local:bob", encrypted_secret=None, config_json={"webhook_url": "https://b.test/hook"})

    class _Result:
        def scalars(self):
            return MagicMock(all=lambda: [alice_channel, bob_channel])

    db = MagicMock()
    db.execute.return_value = _Result()
    delivered: list[str] = []
    monkeypatch.setattr(
        "secaudit_core.notifications.deliver_to_channel",
        lambda channel, _payload, _settings: delivered.append(channel.name),
    )

    settings = MagicMock(secret_key="x" * 32)
    result = deliver_notifications(db, payload, settings)
    assert result["sent"] == 1
    assert delivered == ["alice-hook"]


@pytest.mark.asyncio
async def test_list_notification_channels_scoped_for_engineer(monkeypatch):
    fake_db = AsyncMock()
    captured: dict[str, str] = {}

    async def _execute(stmt):
        captured["sql"] = str(stmt)
        return type("R", (), {"scalars": lambda self: type("S", (), {"all": lambda self: []})()})()

    fake_db.execute = _execute
    monkeypatch.setattr(object_rbac_service.settings, "object_rbac_enabled", True)

    await notifications_router.list_notification_channels(
        db=fake_db,
        user=AuthUser(sub="local:eng1", username="eng1", roles=[UserRole.OPERATOR.value]),
    )
    assert "notification_channels.owner_sub" in captured["sql"]


@pytest.mark.asyncio
async def test_get_notification_channel_denies_foreign_engineer():
    channel = NotificationChannel(
        id=5,
        name="foreign",
        channel_type=NotificationChannelType.SLACK,
        is_active=True,
        events=[NotificationEventType.RUN_FAILED.value],
        owner_sub="local:bob",
    )
    fake_db = AsyncMock()
    fake_db.get = AsyncMock(return_value=channel)

    with pytest.raises(HTTPException) as exc:
        await notifications_router.get_notification_channel(
            channel_id=5,
            db=fake_db,
            user=AuthUser(sub="local:alice", username="alice", roles=[UserRole.OPERATOR.value]),
        )
    assert exc.value.status_code == 404


def test_assign_notification_channel_owner_engineer_only():
    channel = NotificationChannel(
        name="mine",
        channel_type=NotificationChannelType.WEBHOOK,
        is_active=True,
        events=[],
    )
    object_rbac_service.assign_notification_channel_owner(
        channel,
        AuthUser(sub="local:eng1", username="eng1", roles=[UserRole.OPERATOR.value]),
    )
    assert channel.owner_sub == "local:eng1"

    platform = NotificationChannel(
        name="platform",
        channel_type=NotificationChannelType.SIEM,
        is_active=True,
        events=[],
    )
    object_rbac_service.assign_notification_channel_owner(
        platform,
        AuthUser(sub="local:admin", username="admin", roles=[UserRole.ADMIN.value]),
    )
    assert platform.owner_sub is None
