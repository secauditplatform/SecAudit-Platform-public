"""Helpers for per-job webhook configuration."""

from __future__ import annotations

from secaudit_core.egress import validate_public_https_url
from secaudit_core.enums import NotificationEventType
from secaudit_core.secrets import encrypt_secret


DEFAULT_WEBHOOK_EVENTS = [
    NotificationEventType.RUN_COMPLETED.value,
    NotificationEventType.RUN_FAILED.value,
]


def normalize_webhook_events(events: list | None) -> list[str]:
    if not events:
        return list(DEFAULT_WEBHOOK_EVENTS)
    return [event.value if hasattr(event, "value") else str(event) for event in events]


def apply_webhook_fields(
    job,
    *,
    settings,
    webhook_enabled: bool | None = None,
    webhook_events: list | None = None,
    webhook_url: str | None = None,
    clear_webhook_url: bool | None = None,
) -> None:
    if webhook_enabled is not None:
        job.webhook_enabled = webhook_enabled
    if webhook_events is not None:
        job.webhook_events = normalize_webhook_events(webhook_events)

    if webhook_url:
        safe_url = validate_public_https_url(webhook_url.strip(), resolve_dns=True)
        job.encrypted_webhook_url = encrypt_secret(safe_url, settings)
    elif clear_webhook_url:
        job.encrypted_webhook_url = None


def webhook_read_fields(job) -> dict:
    return {
        "webhook_enabled": bool(job.webhook_enabled),
        "webhook_events": normalize_webhook_events(job.webhook_events),
        "has_webhook_url": bool(job.encrypted_webhook_url),
    }
