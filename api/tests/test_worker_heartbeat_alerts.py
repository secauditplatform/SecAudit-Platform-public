"""Unit tests for stale worker heartbeat evaluation and platform alerts."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from secaudit_core.celery_observability import evaluate_worker_heartbeat
from secaudit_core.enums import NotificationChannelType, NotificationEventType
from secaudit_core.models import NotificationChannel
from secaudit_core.notifications import (
    _format_message,
    build_platform_notification_payload,
    deliver_notifications,
)


def test_evaluate_worker_heartbeat_rising_edge_stale(monkeypatch):
    monkeypatch.setattr(
        "secaudit_core.celery_observability.worker_heartbeat_age_seconds",
        lambda _url: 250.0,
    )
    monkeypatch.setattr(
        "secaudit_core.celery_observability.get_worker_heartbeat_alert_state",
        lambda _url: "ok",
    )
    set_state = MagicMock()
    monkeypatch.setattr(
        "secaudit_core.celery_observability.set_worker_heartbeat_alert_state",
        set_state,
    )

    result = evaluate_worker_heartbeat("redis://localhost/0", max_age_seconds=120)

    assert result["stale"] is True
    assert result["transition"] == "stale"
    set_state.assert_called_once()
    assert set_state.call_args.args[1] == "stale"


def test_evaluate_worker_heartbeat_no_repeat_while_stale(monkeypatch):
    monkeypatch.setattr(
        "secaudit_core.celery_observability.worker_heartbeat_age_seconds",
        lambda _url: None,
    )
    monkeypatch.setattr(
        "secaudit_core.celery_observability.get_worker_heartbeat_alert_state",
        lambda _url: "stale",
    )
    set_state = MagicMock()
    monkeypatch.setattr(
        "secaudit_core.celery_observability.set_worker_heartbeat_alert_state",
        set_state,
    )

    result = evaluate_worker_heartbeat("redis://localhost/0", max_age_seconds=120)

    assert result["stale"] is True
    assert result["transition"] is None
    set_state.assert_not_called()


def test_evaluate_worker_heartbeat_recovered(monkeypatch):
    monkeypatch.setattr(
        "secaudit_core.celery_observability.worker_heartbeat_age_seconds",
        lambda _url: 12.0,
    )
    monkeypatch.setattr(
        "secaudit_core.celery_observability.get_worker_heartbeat_alert_state",
        lambda _url: "stale",
    )
    set_state = MagicMock()
    monkeypatch.setattr(
        "secaudit_core.celery_observability.set_worker_heartbeat_alert_state",
        set_state,
    )

    result = evaluate_worker_heartbeat("redis://localhost/0", max_age_seconds=120)

    assert result["stale"] is False
    assert result["transition"] == "recovered"
    assert set_state.call_args.args[1] == "ok"


def test_build_platform_notification_payload_embeds_audit():
    payload = build_platform_notification_payload(
        trigger_events=[NotificationEventType.WORKER_HEARTBEAT_STALE.value],
        status="failed",
        summary="Workers down",
        detail="Heartbeat missing",
        age_seconds=None,
        max_age_seconds=120,
        frontend_base_url="http://localhost:5173",
    )
    assert payload["payload_type"] == "platform"
    assert payload["audit"]["action"] == "worker.heartbeat_stale"
    assert payload["audit"]["outcome"] == "failed"
    title, body = _format_message(payload)
    assert "Worker heartbeat stale" in title
    assert "Workers down" in body
    assert "missing" in body.lower()


def test_deliver_platform_payload_to_webhook_and_siem(monkeypatch):
    payload = build_platform_notification_payload(
        trigger_events=[NotificationEventType.WORKER_HEARTBEAT_STALE.value],
        status="failed",
        summary="Workers down",
        detail="stale",
        age_seconds=200,
        max_age_seconds=120,
    )
    webhook = NotificationChannel(
        id=1,
        name="ops-hook",
        channel_type=NotificationChannelType.WEBHOOK,
        is_active=True,
        events=[NotificationEventType.WORKER_HEARTBEAT_STALE.value],
        encrypted_secret=None,
        config_json={"webhook_url": "https://example.test/hook"},
    )
    siem = NotificationChannel(
        id=2,
        name="siem",
        channel_type=NotificationChannelType.SIEM,
        is_active=True,
        events=[NotificationEventType.WORKER_HEARTBEAT_STALE.value],
        encrypted_secret=None,
        config_json={"webhook_url": "https://example.test/siem", "format": "json"},
    )

    class _Result:
        def scalars(self):
            return SimpleNamespace(all=lambda: [webhook, siem])

    db = MagicMock()
    db.execute.return_value = _Result()

    delivered: list[str] = []

    def fake_deliver_to_channel(channel, _payload, _settings):
        delivered.append(f"channel:{channel.name}")

    def fake_deliver_siem(channel, _payload, _settings):
        delivered.append(f"siem:{channel.name}")

    monkeypatch.setattr(
        "secaudit_core.notifications.deliver_to_channel",
        fake_deliver_to_channel,
    )
    monkeypatch.setattr(
        "secaudit_core.siem_export.deliver_siem_to_channel",
        fake_deliver_siem,
    )

    settings = SimpleNamespace(secret_key="x" * 32, notifications_enabled=True)
    result = deliver_notifications(db, payload, settings)

    assert result["sent"] == 2
    assert delivered == ["channel:ops-hook", "siem:siem"]
