import pytest

from secaudit_core.enums import JobStatus, NotificationChannelType, NotificationEventType
from secaudit_core.models import NotificationChannel
from secaudit_core.notifications import (
    _channel_matches,
    build_run_notification_payload,
    build_test_payload,
    deliver_to_channel,
    events_for_terminal_status,
)


def test_events_for_terminal_status_failed():
    assert events_for_terminal_status(JobStatus.FAILED) == [NotificationEventType.RUN_FAILED.value]


def test_events_for_terminal_status_completed():
    assert events_for_terminal_status(JobStatus.COMPLETED) == [NotificationEventType.RUN_COMPLETED.value]


def test_events_for_terminal_status_dispatch():
    assert events_for_terminal_status(JobStatus.FAILED, source="dispatch") == [
        NotificationEventType.DISPATCH_FAILED.value
    ]


def test_events_for_terminal_status_stale():
    events = events_for_terminal_status(JobStatus.FAILED, source="stale")
    assert NotificationEventType.RUN_STALE.value in events
    assert NotificationEventType.RUN_FAILED.value in events


def test_channel_matches_active_subscription():
    channel = NotificationChannel(
        id=1,
        name="ops",
        channel_type=NotificationChannelType.SLACK,
        is_active=True,
        events=[NotificationEventType.RUN_FAILED.value],
    )
    assert _channel_matches(channel, [NotificationEventType.RUN_FAILED.value]) is True
    assert _channel_matches(channel, [NotificationEventType.RUN_COMPLETED.value]) is False


def test_channel_matches_inactive():
    channel = NotificationChannel(
        id=1,
        name="ops",
        channel_type=NotificationChannelType.SLACK,
        is_active=False,
        events=[NotificationEventType.RUN_FAILED.value],
    )
    assert _channel_matches(channel, [NotificationEventType.RUN_FAILED.value]) is False


def test_build_run_notification_payload_contains_link():
    payload = build_run_notification_payload(
        trigger_events=[NotificationEventType.RUN_FAILED.value],
        run_kind="job",
        run_id=42,
        job_id=7,
        job_name="Linux audit",
        status=JobStatus.FAILED.value,
        error_message="boom",
        frontend_base_url="http://localhost:5173",
    )
    assert payload["run_url"] == "http://localhost:5173/jobs?run=42"
    assert payload["job_name"] == "Linux audit"
    assert payload["error_message"] == "boom"


def test_deliver_webhook_channel_posts_json(monkeypatch):
    captured: dict = {}

    class _Response:
        def raise_for_status(self):
            return None

    def _fake_post(url, json, headers, timeout):
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        return _Response()

    monkeypatch.setattr("secaudit_core.notifications.httpx.post", _fake_post)
    channel = NotificationChannel(
        id=1,
        name="hook",
        channel_type=NotificationChannelType.WEBHOOK,
        is_active=True,
        events=[NotificationEventType.RUN_FAILED.value],
        encrypted_secret="encrypted",
    )

    class _Settings:
        secret_key = "test-key"
        frontend_base_url = "http://localhost:5173"

    monkeypatch.setattr(
        "secaudit_core.notifications.decrypt_secret",
        lambda _token, _key: "https://example.com/hook",
    )

    payload = build_test_payload(_Settings())
    deliver_to_channel(channel, payload, _Settings())
    assert captured["url"] == "https://example.com/hook"
    assert captured["json"]["job_name"] == "SecAudit test notification"


def test_deliver_per_job_webhook_posts_json(monkeypatch):
    captured: dict = {}

    class _Response:
        def raise_for_status(self):
            return None

    def _fake_post(url, json, headers=None, timeout=30.0):
        captured["url"] = url
        captured["json"] = json
        return _Response()

    monkeypatch.setattr("secaudit_core.notifications.httpx.post", _fake_post)
    monkeypatch.setattr(
        "secaudit_core.notifications.decrypt_secret",
        lambda _token, _key: "https://example.com/job-hook",
    )

    from secaudit_core.models import Job

    class _Settings:
        secret_key = "test-key"

    job = Job(
        id=7,
        name="Linux audit",
        webhook_enabled=True,
        encrypted_webhook_url="encrypted",
        webhook_events=[NotificationEventType.RUN_FAILED.value],
    )

    class _Session:
        def get(self, model, job_id):
            assert job_id == 7
            return job

    payload = build_run_notification_payload(
        trigger_events=[NotificationEventType.RUN_FAILED.value],
        run_kind="job",
        run_id=42,
        job_id=7,
        job_name="Linux audit",
        status=JobStatus.FAILED.value,
    )

    from secaudit_core.notifications import deliver_per_job_webhook

    result = deliver_per_job_webhook(_Session(), payload, _Settings())
    assert result["sent"] == 1
    assert captured["url"] == "https://example.com/job-hook"
    assert captured["json"]["run_id"] == 42


def test_notifications_router_requires_auth():
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        response = client.get("/api/v1/notifications")
    assert response.status_code == 401
