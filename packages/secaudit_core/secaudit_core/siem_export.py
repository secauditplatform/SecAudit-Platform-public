"""SIEM export: CEF and JSON webhook delivery for AuditLog events."""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from typing import Any

import httpx

from secaudit_core.celery_dispatch import send_task
from secaudit_core.egress import pinned_https_url, sanitize_outbound_headers, validate_public_https_url
from secaudit_core.enums import NotificationChannelType, NotificationEventType
from secaudit_core.models import NotificationChannel
from secaudit_core.secrets import decrypt_secret
from secaudit_core.settings import SecAuditSettings
from secaudit_core.sensitive_data import redact_sensitive

logger = logging.getLogger(__name__)

CEF_VERSION = 0
DEFAULT_VENDOR = "SecAudit"
DEFAULT_PRODUCT = "Compliance Platform"

OUTCOME_SEVERITY = {
    "success": 3,
    "failed": 7,
    "denied": 8,
}

_CEF_ESCAPE_RE = re.compile(r"[\\|=]")


def audit_trigger_events(outcome: str) -> list[str]:
    events = [NotificationEventType.AUDIT_EVENT.value]
    if (outcome or "").lower() == "failed":
        events.append(NotificationEventType.AUDIT_FAILED.value)
    return events


def audit_log_to_dict(event: Any) -> dict[str, Any]:
    """Serialize an AuditLog ORM row or audit payload into a transport dict."""
    created_at = getattr(event, "created_at", None)
    if isinstance(created_at, datetime):
        ts = created_at.astimezone(UTC).isoformat()
    elif created_at:
        ts = str(created_at)
    else:
        ts = datetime.now(UTC).isoformat()

    metadata = getattr(event, "metadata_json", None) or {}
    if not isinstance(metadata, dict):
        metadata = {}

    return {
        "id": getattr(event, "id", None),
        "timestamp": ts,
        "actor_username": getattr(event, "actor_username", "unknown"),
        "actor_roles": getattr(event, "actor_roles", None) or [],
        "action": getattr(event, "action", ""),
        "resource_type": getattr(event, "resource_type", ""),
        "resource_id": getattr(event, "resource_id", None),
        "resource_name": getattr(event, "resource_name", None),
        "outcome": getattr(event, "outcome", "success"),
        "ip_address": getattr(event, "ip_address", None),
        "user_agent": getattr(event, "user_agent", None),
        "metadata": redact_sensitive(metadata),
    }


def build_audit_siem_payload(*, audit_event: dict[str, Any]) -> dict[str, Any]:
    outcome = str(audit_event.get("outcome") or "success")
    return {
        "payload_type": "audit",
        "trigger_events": audit_trigger_events(outcome),
        "audit": audit_event,
    }


def _cef_escape(value: Any) -> str:
    text = str(value) if value is not None else ""
    return _CEF_ESCAPE_RE.sub(lambda m: "\\" + m.group(0), text.replace("\n", " ").replace("\r", " "))


def format_audit_cef(
    audit_event: dict[str, Any],
    settings: SecAuditSettings,
    *,
    vendor: str = DEFAULT_VENDOR,
    product: str = DEFAULT_PRODUCT,
) -> str:
    """Format an audit event as a CEF syslog line."""
    action = audit_event.get("action") or "audit"
    outcome = audit_event.get("outcome") or "success"
    severity = OUTCOME_SEVERITY.get(str(outcome).lower(), 5)
    name = f"{audit_event.get('resource_type', 'resource')}:{action}"
    extensions = {
        "rt": audit_event.get("timestamp"),
        "suser": audit_event.get("actor_username"),
        "src": audit_event.get("ip_address"),
        "outcome": outcome,
        "cs1": audit_event.get("resource_type"),
        "cs1Label": "resourceType",
        "cs2": audit_event.get("resource_id"),
        "cs2Label": "resourceId",
        "cs3": audit_event.get("resource_name"),
        "cs3Label": "resourceName",
        "request": audit_event.get("user_agent"),
        "app": f"{product}/{settings.app_version}",
    }
    roles = audit_event.get("actor_roles") or []
    if roles:
        extensions["cs4"] = ",".join(str(role) for role in roles)
        extensions["cs4Label"] = "actorRoles"

    metadata = audit_event.get("metadata") or {}
    if metadata:
        extensions["cs5"] = json.dumps(metadata, ensure_ascii=False, separators=(",", ":"))
        extensions["cs5Label"] = "metadata"

    ext_parts = []
    for key, value in extensions.items():
        if value is None or value == "" or key.endswith("Label"):
            continue
        ext_parts.append(f"{key}={_cef_escape(value)}")

    extension = " ".join(ext_parts)
    return (
        f"CEF:{CEF_VERSION}|{_cef_escape(vendor)}|{_cef_escape(product)}|"
        f"{_cef_escape(settings.app_version)}|{_cef_escape(action)}|"
        f"{_cef_escape(name)}|{severity}|{extension}"
    )


def format_audit_json(
    audit_event: dict[str, Any],
    settings: SecAuditSettings,
    *,
    vendor: str = DEFAULT_VENDOR,
    product: str = DEFAULT_PRODUCT,
) -> dict[str, Any]:
    """Format an audit event as structured JSON for SIEM ingestion."""
    outcome = str(audit_event.get("outcome") or "success").lower()
    event_type = "error" if outcome == "failed" else "info"
    return {
        "@timestamp": audit_event.get("timestamp"),
        "event": {
            "action": audit_event.get("action"),
            "category": ["configuration", "iam"],
            "dataset": "secaudit.audit",
            "kind": "event",
            "outcome": outcome,
            "type": [event_type],
            "id": audit_event.get("id"),
        },
        "user": {
            "name": audit_event.get("actor_username"),
            "roles": audit_event.get("actor_roles") or [],
        },
        "source": {
            "ip": audit_event.get("ip_address"),
        },
        "user_agent": {
            "original": audit_event.get("user_agent"),
        },
        "secaudit": {
            "resource_type": audit_event.get("resource_type"),
            "resource_id": audit_event.get("resource_id"),
            "resource_name": audit_event.get("resource_name"),
            "metadata": audit_event.get("metadata") or {},
        },
        "agent": {
            "type": "secaudit",
            "version": settings.app_version,
            "vendor": vendor,
            "product": product,
        },
    }


def _resolve_siem_url(channel: NotificationChannel, settings: SecAuditSettings) -> str | None:
    if channel.encrypted_secret:
        return decrypt_secret(channel.encrypted_secret, settings)
    config = channel.config_json or {}
    url = config.get("webhook_url") or config.get("url")
    return str(url) if url else None


def deliver_siem_to_channel(
    channel: NotificationChannel,
    payload: dict[str, Any],
    settings: SecAuditSettings,
) -> None:
    url = _resolve_siem_url(channel, settings)
    if not url:
        raise ValueError("SIEM webhook URL is not configured")

    audit_event = payload.get("audit") or payload
    config = channel.config_json or {}
    vendor = str(config.get("vendor") or DEFAULT_VENDOR)
    product = str(config.get("product") or DEFAULT_PRODUCT)
    fmt = str(config.get("format") or "json").lower()

    headers: dict[str, str] = {}
    if audit_event.get("id") is not None:
        headers["Idempotency-Key"] = f"secaudit-audit-{audit_event['id']}"
    extra = config.get("headers")
    if isinstance(extra, dict):
        headers.update(sanitize_outbound_headers({str(k): str(v) for k, v in extra.items()}))

    safe_url, pin_headers = pinned_https_url(url)
    headers.update(pin_headers)
    if fmt == "cef":
        body = format_audit_cef(audit_event, settings, vendor=vendor, product=product)
        headers.setdefault("Content-Type", "text/plain; charset=utf-8")
        response = httpx.post(
            safe_url,
            content=body,
            headers=headers,
            timeout=30.0,
            follow_redirects=False,
        )
    else:
        body = format_audit_json(audit_event, settings, vendor=vendor, product=product)
        headers.setdefault("Content-Type", "application/json")
        response = httpx.post(
            safe_url,
            json=body,
            headers=headers,
            timeout=30.0,
            follow_redirects=False,
        )
    response.raise_for_status()


def enqueue_audit_siem_export(
    *,
    broker_url: str,
    settings: SecAuditSettings,
    audit_event: dict[str, Any],
) -> None:
    if not settings.notifications_enabled:
        return
    payload = build_audit_siem_payload(audit_event=audit_event)
    try:
        send_task(
            "app.tasks.maintenance.send_notification",
            [payload],
            broker_url=broker_url,
            queue="maintenance",
        )
    except Exception:
        logger.error("Failed to enqueue SIEM export for audit event %s", audit_event.get("id"), exc_info=True)


def build_siem_test_payload(settings: SecAuditSettings) -> dict[str, Any]:
    return build_audit_siem_payload(
        audit_event={
            "id": 0,
            "timestamp": datetime.now(UTC).isoformat(),
            "actor_username": "secaudit-test",
            "actor_roles": ["admin"],
            "action": "notification_channel.test",
            "resource_type": "notification_channel",
            "resource_id": "0",
            "resource_name": "SIEM test channel",
            "outcome": "success",
            "ip_address": "127.0.0.1",
            "user_agent": "SecAudit/SIEM-Test",
            "metadata": {"message": "This is a test SIEM export from SecAudit."},
        }
    )
