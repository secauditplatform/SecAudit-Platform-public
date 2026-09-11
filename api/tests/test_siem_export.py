import pytest

from secaudit_core.enums import NotificationChannelType, NotificationEventType
from secaudit_core.models import NotificationChannel
from secaudit_core.notifications import deliver_notifications
from secaudit_core.siem_export import (
    audit_trigger_events,
    build_audit_siem_payload,
    deliver_siem_to_channel,
    format_audit_cef,
    format_audit_json,
)


class _Settings:
    secret_key = "test-key"
    app_version = "1.2.3"
    notifications_enabled = True
    frontend_base_url = "http://localhost:5173"


SAMPLE_AUDIT = {
    "id": 42,
    "timestamp": "2026-07-12T10:00:00+00:00",
    "actor_username": "alice",
    "actor_roles": ["admin"],
    "action": "job.create",
    "resource_type": "job",
    "resource_id": "7",
    "resource_name": "Linux audit",
    "outcome": "success",
    "ip_address": "10.0.0.5",
    "user_agent": "Mozilla/5.0",
    "metadata": {"job_id": 7},
}


def test_audit_trigger_events_success():
    assert audit_trigger_events("success") == [NotificationEventType.AUDIT_EVENT.value]


def test_audit_trigger_events_failed():
    events = audit_trigger_events("failed")
    assert NotificationEventType.AUDIT_EVENT.value in events
    assert NotificationEventType.AUDIT_FAILED.value in events


def test_build_audit_siem_payload_marks_audit_type():
    payload = build_audit_siem_payload(audit_event=SAMPLE_AUDIT)
    assert payload["payload_type"] == "audit"
    assert payload["audit"]["action"] == "job.create"
    assert NotificationEventType.AUDIT_EVENT.value in payload["trigger_events"]


def test_format_audit_cef_contains_core_fields():
    line = format_audit_cef(SAMPLE_AUDIT, _Settings())
    assert line.startswith("CEF:0|")
    assert "job.create" in line
    assert "alice" in line
    assert "cs1=job" in line


def test_format_audit_json_ecs_shape():
    body = format_audit_json(SAMPLE_AUDIT, _Settings())
    assert body["@timestamp"] == SAMPLE_AUDIT["timestamp"]
    assert body["event"]["action"] == "job.create"
    assert body["user"]["name"] == "alice"
    assert body["secaudit"]["resource_type"] == "job"
    assert body["agent"]["version"] == "1.2.3"


def test_deliver_siem_json_posts_structured_body(monkeypatch):
    captured: dict = {}

    class _Response:
        def raise_for_status(self):
            return None

    def _fake_post(url, json=None, content=None, headers=None, timeout=30.0):
        captured["url"] = url
        captured["json"] = json
        captured["content"] = content
        captured["headers"] = headers
        return _Response()

    monkeypatch.setattr("secaudit_core.siem_export.httpx.post", _fake_post)
    monkeypatch.setattr(
        "secaudit_core.siem_export.decrypt_secret",
        lambda _token, _key: "https://siem.example.com/ingest",
    )

    channel = NotificationChannel(
        id=1,
        name="siem",
        channel_type=NotificationChannelType.SIEM,
        is_active=True,
        events=[NotificationEventType.AUDIT_EVENT.value],
        encrypted_secret="encrypted",
        config_json={"format": "json"},
    )
    payload = build_audit_siem_payload(audit_event=SAMPLE_AUDIT)
    deliver_siem_to_channel(channel, payload, _Settings())

    assert captured["url"] == "https://siem.example.com/ingest"
    assert captured["json"]["event"]["action"] == "job.create"
    assert captured["headers"]["Content-Type"] == "application/json"
    assert captured["headers"]["Idempotency-Key"] == "secaudit-audit-42"


def test_deliver_siem_cef_posts_plaintext(monkeypatch):
    captured: dict = {}

    class _Response:
        def raise_for_status(self):
            return None

    def _fake_post(url, json=None, content=None, headers=None, timeout=30.0):
        captured["url"] = url
        captured["json"] = json
        captured["content"] = content
        captured["headers"] = headers
        return _Response()

    monkeypatch.setattr("secaudit_core.siem_export.httpx.post", _fake_post)
    monkeypatch.setattr(
        "secaudit_core.siem_export.decrypt_secret",
        lambda _token, _key: "https://siem.example.com/cef",
    )

    channel = NotificationChannel(
        id=2,
        name="siem-cef",
        channel_type=NotificationChannelType.SIEM,
        is_active=True,
        events=[NotificationEventType.AUDIT_EVENT.value],
        encrypted_secret="encrypted",
        config_json={"format": "cef"},
    )
    payload = build_audit_siem_payload(audit_event=SAMPLE_AUDIT)
    deliver_siem_to_channel(channel, payload, _Settings())

    assert captured["url"] == "https://siem.example.com/cef"
    assert captured["json"] is None
    assert isinstance(captured["content"], str)
    assert captured["content"].startswith("CEF:")
    assert captured["headers"]["Content-Type"] == "text/plain; charset=utf-8"


def test_deliver_notifications_routes_audit_only_to_siem(monkeypatch):
    delivered: list[str] = []

    def _fake_run(channel, payload, settings):
        delivered.append(channel.channel_type.value)

    monkeypatch.setattr("secaudit_core.siem_export.deliver_siem_to_channel", _fake_run)
    monkeypatch.setattr(
        "secaudit_core.notifications.deliver_to_channel",
        lambda channel, payload, settings: delivered.append(channel.channel_type.value),
    )

    class _Session:
        def execute(self, _stmt):
            return self

        def scalars(self):
            return self

        def all(self):
            return [
                NotificationChannel(
                    id=1,
                    name="slack",
                    channel_type=NotificationChannelType.SLACK,
                    is_active=True,
                    events=[NotificationEventType.AUDIT_EVENT.value],
                ),
                NotificationChannel(
                    id=2,
                    name="siem",
                    channel_type=NotificationChannelType.SIEM,
                    is_active=True,
                    events=[NotificationEventType.AUDIT_EVENT.value],
                    encrypted_secret="encrypted",
                ),
            ]

    payload = build_audit_siem_payload(audit_event=SAMPLE_AUDIT)
    result = deliver_notifications(_Session(), payload, _Settings())

    assert delivered == ["siem"]
    assert result["sent"] == 1
    assert result["skipped"] == 1
