"""Outbound notifications for job/remediation run events."""

from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from secaudit_core.celery_dispatch import send_task
from secaudit_core.enums import JobStatus, NotificationChannelType, NotificationEventType
from secaudit_core.models import NotificationChannel
from secaudit_core.secrets import decrypt_secret
from secaudit_core.settings import SecAuditSettings
from secaudit_core.sensitive_data import redact_sensitive

logger = logging.getLogger(__name__)

DEFAULT_WEBHOOK_EVENTS = [
    NotificationEventType.RUN_COMPLETED.value,
    NotificationEventType.RUN_FAILED.value,
]

RUN_KIND_LABELS = {
    "job": "Compliance job",
    "remediation": "Remediation job",
    "inventory": "Inventory scan",
}

EVENT_LABELS = {
    NotificationEventType.RUN_FAILED.value: "Run failed",
    NotificationEventType.RUN_COMPLETED.value: "Run completed",
    NotificationEventType.RUN_STALE.value: "Stale run (worker lost)",
    NotificationEventType.DISPATCH_FAILED.value: "Dispatch failed",
    NotificationEventType.WORKER_HEARTBEAT_STALE.value: "Worker heartbeat stale",
    NotificationEventType.WORKER_HEARTBEAT_RECOVERED.value: "Worker heartbeat recovered",
}


def events_for_terminal_status(
    status: JobStatus | str,
    *,
    source: str = "finished",
) -> list[str]:
    value = status.value if isinstance(status, JobStatus) else str(status)
    if source == "dispatch":
        return [NotificationEventType.DISPATCH_FAILED.value]
    if source == "stale":
        return [
            NotificationEventType.RUN_STALE.value,
            NotificationEventType.RUN_FAILED.value,
        ]
    if value == JobStatus.FAILED.value:
        return [NotificationEventType.RUN_FAILED.value]
    if value == JobStatus.COMPLETED.value:
        return [NotificationEventType.RUN_COMPLETED.value]
    return []


def build_run_notification_payload(
    *,
    trigger_events: list[str],
    run_kind: str,
    run_id: int,
    job_id: int | None,
    job_name: str,
    status: str,
    error_message: str | None = None,
    owner_sub: str | None = None,
    frontend_base_url: str = "http://localhost:5173",
) -> dict[str, Any]:
    path_by_kind = {
        "job": f"/jobs?run={run_id}",
        "remediation": f"/remediation?run={run_id}",
        "inventory": f"/hosts",
    }
    path = path_by_kind.get(run_kind, "/")
    base = frontend_base_url.rstrip("/")
    return {
        "trigger_events": trigger_events,
        "event_label": EVENT_LABELS.get(trigger_events[0], trigger_events[0]) if trigger_events else "Event",
        "run_kind": run_kind,
        "run_kind_label": RUN_KIND_LABELS.get(run_kind, run_kind),
        "run_id": run_id,
        "job_id": job_id,
        "job_name": job_name,
        "status": status,
        "error_message": error_message,
        "owner_sub": owner_sub,
        "run_url": f"{base}{path}",
    }


def enqueue_run_notification(
    *,
    broker_url: str,
    settings: SecAuditSettings,
    trigger_events: list[str],
    run_kind: str,
    run_id: int,
    job_id: int | None,
    job_name: str,
    status: str,
    error_message: str | None = None,
    owner_sub: str | None = None,
) -> None:
    if not settings.notifications_enabled or not trigger_events:
        return
    payload = build_run_notification_payload(
        trigger_events=trigger_events,
        run_kind=run_kind,
        run_id=run_id,
        job_id=job_id,
        job_name=job_name,
        status=status,
        error_message=error_message,
        owner_sub=owner_sub,
        frontend_base_url=settings.frontend_base_url,
    )
    try:
        send_task(
            "app.tasks.maintenance.send_notification",
            [payload],
            broker_url=broker_url,
            queue="maintenance",
        )
    except Exception:
        logger.error("Failed to enqueue notification for run %s", run_id, exc_info=True)


def build_platform_notification_payload(
    *,
    trigger_events: list[str],
    status: str,
    summary: str,
    detail: str | None = None,
    age_seconds: float | None = None,
    max_age_seconds: int | None = None,
    frontend_base_url: str = "http://localhost:5173",
) -> dict[str, Any]:
    from datetime import UTC, datetime

    event = trigger_events[0] if trigger_events else "platform_event"
    audit_action = (
        "worker.heartbeat_stale"
        if event == NotificationEventType.WORKER_HEARTBEAT_STALE.value
        else "worker.heartbeat_recovered"
        if event == NotificationEventType.WORKER_HEARTBEAT_RECOVERED.value
        else f"platform.{event}"
    )
    outcome = "failed" if status == "failed" else "success"
    metadata: dict[str, Any] = {}
    if age_seconds is not None:
        metadata["heartbeat_age_seconds"] = round(age_seconds, 2)
    if max_age_seconds is not None:
        metadata["max_age_seconds"] = max_age_seconds
    if detail:
        metadata["detail"] = detail

    base = frontend_base_url.rstrip("/")
    return {
        "payload_type": "platform",
        "trigger_events": trigger_events,
        "event_label": EVENT_LABELS.get(event, event),
        "status": status,
        "summary": summary,
        "error_message": detail if status == "failed" else None,
        "detail": detail,
        "age_seconds": age_seconds,
        "max_age_seconds": max_age_seconds,
        "run_url": f"{base}/settings?tab=notifications",
        "audit": {
            "id": None,
            "timestamp": datetime.now(UTC).isoformat(),
            "actor_username": "system",
            "actor_roles": ["system"],
            "action": audit_action,
            "resource_type": "celery_worker",
            "resource_id": "heartbeat",
            "resource_name": "Celery worker heartbeat",
            "outcome": outcome,
            "ip_address": None,
            "user_agent": None,
            "metadata": metadata,
        },
    }


def enqueue_platform_notification(
    *,
    broker_url: str,
    settings: SecAuditSettings,
    trigger_events: list[str],
    status: str,
    summary: str,
    detail: str | None = None,
    age_seconds: float | None = None,
    max_age_seconds: int | None = None,
) -> None:
    if not settings.notifications_enabled or not trigger_events:
        return
    payload = build_platform_notification_payload(
        trigger_events=trigger_events,
        status=status,
        summary=summary,
        detail=detail,
        age_seconds=age_seconds,
        max_age_seconds=max_age_seconds,
        frontend_base_url=settings.frontend_base_url,
    )
    try:
        send_task(
            "app.tasks.maintenance.send_notification",
            [payload],
            broker_url=broker_url,
            queue="maintenance",
        )
    except Exception:
        logger.error("Failed to enqueue platform notification %s", trigger_events, exc_info=True)


def _format_message(payload: dict[str, Any]) -> tuple[str, str]:
    title = f"SecAudit: {payload.get('event_label', 'Notification')}"
    if payload.get("payload_type") == "platform":
        lines = [
            payload.get("summary") or payload.get("event_label") or "Platform event",
        ]
        if payload.get("detail"):
            lines.append(f"Detail: {payload['detail']}")
        age = payload.get("age_seconds")
        max_age = payload.get("max_age_seconds")
        if age is None and max_age is not None:
            lines.append(f"Heartbeat age: missing (max {max_age}s)")
        elif age is not None and max_age is not None:
            lines.append(f"Heartbeat age: {int(age)}s (max {max_age}s)")
        elif age is not None:
            lines.append(f"Heartbeat age: {int(age)}s")
        if payload.get("run_url"):
            lines.append(f"Open: {payload['run_url']}")
        return title, "\n".join(lines)

    lines = [
        f"{payload.get('run_kind_label', 'Run')} #{payload.get('run_id')}",
        f"Job: {payload.get('job_name', '—')}",
        f"Status: {payload.get('status', '—')}",
    ]
    if payload.get("error_message"):
        lines.append(f"Error: {payload['error_message']}")
    if payload.get("run_url"):
        lines.append(f"Open: {payload['run_url']}")
    body = "\n".join(lines)
    return title, body


def _channel_matches(channel: NotificationChannel, trigger_events: list[str]) -> bool:
    if not channel.is_active:
        return False
    subscribed = set(channel.events or [])
    return bool(subscribed.intersection(trigger_events))


def _channel_owner_matches(channel: NotificationChannel, payload: dict[str, Any]) -> bool:
    """Scope delivery: platform/audit → platform channels only; runs → owner or platform."""
    payload_type = payload.get("payload_type", "run")
    channel_owner = channel.owner_sub
    if payload_type in {"audit", "platform"}:
        return channel_owner is None
    run_owner = payload.get("owner_sub")
    if channel_owner is None:
        return True
    return run_owner is not None and channel_owner == run_owner


def _job_webhook_matches(job, trigger_events: list[str]) -> bool:
    if not job or not getattr(job, "webhook_enabled", False):
        return False
    if not getattr(job, "encrypted_webhook_url", None):
        return False
    subscribed = set(job.webhook_events or DEFAULT_WEBHOOK_EVENTS)
    return bool(subscribed.intersection(trigger_events))


def deliver_per_job_webhook(db: Session, payload: dict[str, Any], settings: SecAuditSettings) -> dict[str, Any]:
    from secaudit_core.models import Job, RemediationJob

    trigger_events = payload.get("trigger_events") or []
    job_id = payload.get("job_id")
    run_kind = payload.get("run_kind")
    if not job_id or payload.get("payload_type") in {"audit", "platform"}:
        return {"sent": 0, "errors": []}

    if run_kind == "job":
        job = db.get(Job, job_id)
    elif run_kind == "remediation":
        job = db.get(RemediationJob, job_id)
    else:
        return {"sent": 0, "errors": []}

    if not _job_webhook_matches(job, trigger_events):
        return {"sent": 0, "errors": []}

    url = decrypt_secret(job.encrypted_webhook_url, settings)
    try:
        _deliver_webhook(url, payload)
        return {"sent": 1, "errors": []}
    except Exception as exc:
        safe_error = redact_sensitive(str(exc))
        logger.warning(
            "Per-job webhook delivery failed for %s job %s: %s",
            run_kind,
            job_id,
            safe_error,
        )
        return {"sent": 0, "errors": [safe_error]}


def _resolve_webhook_url(channel: NotificationChannel, settings: SecAuditSettings) -> str | None:
    if channel.encrypted_secret:
        return decrypt_secret(channel.encrypted_secret, settings)
    config = channel.config_json or {}
    url = config.get("webhook_url")
    return str(url) if url else None


def _normalize_email_recipients(raw: object) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        return [part.strip() for part in raw.split(",") if part.strip()]
    if isinstance(raw, (list, tuple, set)):
        return [str(item).strip() for item in raw if str(item).strip()]
    return []


def _deliver_email(channel: NotificationChannel, payload: dict[str, Any], settings: SecAuditSettings) -> None:
    config = channel.config_json or {}
    recipients = _normalize_email_recipients(config.get("to_addresses"))
    if not recipients:
        raise ValueError("Email channel has no recipients")

    smtp_host = (config.get("smtp_host") or settings.smtp_host or "").strip()
    if not smtp_host:
        raise ValueError(
            "SMTP host is not configured. Set SMTP_HOST in .env or smtp_host on the channel."
        )

    smtp_port = int(config.get("smtp_port") or settings.smtp_port or 587)
    smtp_user = config.get("smtp_user") or settings.smtp_user
    smtp_password = None
    if channel.encrypted_secret:
        smtp_password = decrypt_secret(channel.encrypted_secret, settings)
    elif settings.smtp_password:
        smtp_password = settings.smtp_password

    from_address = config.get("from_address") or settings.smtp_from or smtp_user
    if not from_address:
        raise ValueError("SMTP from address is not configured")

    subject, body = _format_message(payload)
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = from_address
    message["To"] = ", ".join(recipients)
    message.set_content(body)

    use_tls = config.get("use_tls")
    if use_tls is None:
        use_tls = settings.smtp_use_tls
    use_tls = bool(use_tls)

    with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as smtp:
        if use_tls:
            smtp.starttls()
        if smtp_user and smtp_password:
            smtp.login(str(smtp_user), str(smtp_password))
        elif smtp_user and not smtp_password:
            raise ValueError("SMTP user is set but password is missing")
        smtp.send_message(message)


def _deliver_webhook(url: str, body: dict[str, Any], headers: dict[str, str] | None = None) -> None:
    request_headers = {"Content-Type": "application/json"}
    if headers:
        request_headers.update(headers)
    response = httpx.post(url, json=body, headers=request_headers, timeout=30.0)
    response.raise_for_status()


def _deliver_slack(channel: NotificationChannel, payload: dict[str, Any], settings: SecAuditSettings) -> None:
    url = _resolve_webhook_url(channel, settings)
    if not url:
        raise ValueError("Slack webhook URL is not configured")
    title, text = _format_message(payload)
    body = {
        "text": title,
        "blocks": [
            {"type": "header", "text": {"type": "plain_text", "text": title}},
            {"type": "section", "text": {"type": "mrkdwn", "text": text.replace("\n", "\n")}},
        ],
    }
    _deliver_webhook(url, body)


def _deliver_teams(channel: NotificationChannel, payload: dict[str, Any], settings: SecAuditSettings) -> None:
    url = _resolve_webhook_url(channel, settings)
    if not url:
        raise ValueError("Teams webhook URL is not configured")
    title, text = _format_message(payload)
    theme_color = "C9190B" if payload.get("status") == JobStatus.FAILED.value else "06C"
    body = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": theme_color,
        "summary": title,
        "sections": [
            {
                "activityTitle": title,
                "text": text,
            }
        ],
    }
    _deliver_webhook(url, body)


def _deliver_generic_webhook(channel: NotificationChannel, payload: dict[str, Any], settings: SecAuditSettings) -> None:
    url = _resolve_webhook_url(channel, settings)
    if not url:
        raise ValueError("Webhook URL is not configured")
    config = channel.config_json or {}
    headers = config.get("headers") if isinstance(config.get("headers"), dict) else None
    _deliver_webhook(url, payload, headers=headers)


def deliver_to_channel(channel: NotificationChannel, payload: dict[str, Any], settings: SecAuditSettings) -> None:
    if channel.channel_type == NotificationChannelType.EMAIL:
        _deliver_email(channel, payload, settings)
        return
    if channel.channel_type == NotificationChannelType.SLACK:
        _deliver_slack(channel, payload, settings)
        return
    if channel.channel_type == NotificationChannelType.TEAMS:
        _deliver_teams(channel, payload, settings)
        return
    if channel.channel_type == NotificationChannelType.WEBHOOK:
        _deliver_generic_webhook(channel, payload, settings)
        return
    raise ValueError(f"Unsupported channel type: {channel.channel_type}")


def deliver_notifications(db: Session, payload: dict[str, Any], settings: SecAuditSettings) -> dict[str, Any]:
    from secaudit_core.siem_export import deliver_siem_to_channel

    trigger_events = payload.get("trigger_events") or []
    payload_type = payload.get("payload_type", "run")
    channels = db.execute(select(NotificationChannel).order_by(NotificationChannel.name)).scalars().all()
    sent = 0
    skipped = 0
    errors: list[str] = []

    for channel in channels:
        if not _channel_matches(channel, trigger_events):
            skipped += 1
            continue
        if not _channel_owner_matches(channel, payload):
            skipped += 1
            continue
        if payload_type == "audit" and channel.channel_type != NotificationChannelType.SIEM:
            skipped += 1
            continue
        if payload_type == "platform" and channel.channel_type == NotificationChannelType.SIEM:
            if not payload.get("audit"):
                skipped += 1
                continue
        elif payload_type != "audit" and channel.channel_type == NotificationChannelType.SIEM:
            skipped += 1
            continue
        try:
            if channel.channel_type == NotificationChannelType.SIEM:
                siem_payload = (
                    payload
                    if payload_type == "audit"
                    else {
                        "payload_type": "audit",
                        "trigger_events": trigger_events,
                        "audit": payload["audit"],
                    }
                )
                deliver_siem_to_channel(channel, siem_payload, settings)
            else:
                deliver_to_channel(channel, payload, settings)
            sent += 1
        except Exception as exc:
            safe_error = redact_sensitive(str(exc))
            logger.warning(
                "Notification delivery failed for channel %s (%s): %s",
                channel.name,
                channel.channel_type.value,
                safe_error,
            )
            errors.append(f"{channel.name}: {safe_error}")

    if payload_type not in {"audit", "platform"}:
        job_webhook_result = deliver_per_job_webhook(db, payload, settings)
        sent += job_webhook_result["sent"]
        errors.extend(job_webhook_result["errors"])

    return {"sent": sent, "skipped": skipped, "errors": errors}


def build_test_payload(settings: SecAuditSettings) -> dict[str, Any]:
    return build_run_notification_payload(
        trigger_events=[NotificationEventType.RUN_FAILED.value],
        run_kind="job",
        run_id=0,
        job_id=None,
        job_name="SecAudit test notification",
        status=JobStatus.FAILED.value,
        error_message="This is a test message from SecAudit.",
        frontend_base_url=settings.frontend_base_url,
    )
