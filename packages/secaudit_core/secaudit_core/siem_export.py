"""SIEM export: CEF and JSON webhook delivery for AuditLog events."""

from __future__ import annotations

import json
import logging
import re
import socket
import ssl
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from secaudit_core.enums import NotificationChannelType, NotificationEventType
from secaudit_core.models import CheckResult, Host, Job, JobRun, NotificationChannel, Profile, Rule
from secaudit_core.secrets import decrypt_secret
from secaudit_core.settings import SecAuditSettings
from secaudit_core.sensitive_data import redact_sensitive
from secaudit_core.task_outbox import enqueue_outbox_row

logger = logging.getLogger(__name__)

CEF_VERSION = 0
DEFAULT_VENDOR = "SecAudit"
DEFAULT_PRODUCT = "Compliance Platform"

OUTCOME_SEVERITY = {
    "success": 3,
    "failed": 7,
    "denied": 8,
}

SIEM_MODES = ("summary", "findings", "delta_only")
_CEF_BY_SEVERITY = {
    "critical": 10,
    "crit": 10,
    "high": 8,
    "medium": 6,
    "med": 6,
    "low": 3,
    "info": 1,
    "informational": 1,
}
# RFC 5424 severity, facility user (1): critical=2, error=3, warning=4, notice=5, info=6.
_SYSLOG_BY_SEVERITY = {
    "critical": 2,
    "crit": 2,
    "high": 3,
    "error": 3,
    "medium": 4,
    "med": 4,
    "warning": 4,
    "low": 5,
    "info": 6,
    "informational": 6,
}
_HOST_SANITIZE_RE = re.compile(r"[^A-Za-z0-9._:-]")
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


def channel_siem_mode(channel: NotificationChannel) -> str:
    raw = str((channel.config_json or {}).get("mode") or "summary").strip().lower()
    return raw if raw in SIEM_MODES else "summary"


def channel_accepts_siem_mode(channel: NotificationChannel, payload: dict[str, Any]) -> bool:
    modes = payload.get("siem_modes") or ["summary"]
    if not isinstance(modes, list):
        modes = ["summary"]
    return channel_siem_mode(channel) in {str(item) for item in modes}


def cef_severity(severity: str | None, outcome: str | None) -> int:
    mapped = _CEF_BY_SEVERITY.get((severity or "").strip().lower())
    if mapped is not None:
        return mapped
    return OUTCOME_SEVERITY.get(str(outcome or "").lower(), 5)


def _syslog_severity(severity: str | None, outcome: str | None) -> int:
    mapped = _SYSLOG_BY_SEVERITY.get((severity or "").strip().lower())
    if mapped is not None:
        return mapped
    if str(outcome or "").lower() in {"failed", "failure", "denied"}:
        return 3
    return 6


def _syslog_hostname(value: str | None) -> str:
    text = (value or "").strip()
    if not text:
        try:
            text = socket.gethostname()
        except OSError:
            text = ""
    text = _HOST_SANITIZE_RE.sub("_", text)[:255]
    return text or "secaudit"


def _status_value(status: object) -> str:
    return status.value if hasattr(status, "value") else str(status or "")


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
    severity = cef_severity(audit_event.get("severity"), outcome)
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
        "dhost": audit_event.get("hostname"),
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
    body: dict[str, Any] = {
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
    hostname = audit_event.get("hostname")
    if hostname:
        body["host"] = {"name": hostname}
    return body


def _resolve_siem_url(channel: NotificationChannel, settings: SecAuditSettings) -> str | None:
    if channel.encrypted_secret:
        return decrypt_secret(channel.encrypted_secret, settings)
    config = channel.config_json or {}
    url = config.get("webhook_url") or config.get("url")
    return str(url) if url else None


def _deliver_syslog(
    config: dict[str, Any],
    message: str,
    settings: SecAuditSettings,
    *,
    severity: str | None = None,
    outcome: str | None = None,
    hostname: str | None = None,
) -> None:
    from secaudit_core.url_safety import validate_outbound_webhook_url

    host = str(config.get("host") or "").strip()
    port = int(config.get("port") or 514)
    protocol = str(config.get("protocol") or "udp").lower()
    if not host:
        raise ValueError("SIEM syslog host is not configured")
    if protocol not in {"udp", "tcp", "tls"}:
        raise ValueError(f"Unsupported syslog protocol: {protocol}")
    if not 1 <= port <= 65535:
        raise ValueError("SIEM syslog port is out of range")
    # SSRF policy only; the https scheme is a placeholder for host/port validation.
    validate_outbound_webhook_url(
        f"https://[{host}]:{port}" if ":" in host else f"https://{host}:{port}",
        allow_private=settings.outbound_webhooks_allow_private,
    )

    # RFC 5424 PRI: facility user (1) plus severity from the finding, not a fixed info.
    pri = 8 + _syslog_severity(severity, outcome)
    line = (
        f"<{pri}>1 {datetime.now(UTC).isoformat()} {_syslog_hostname(hostname)} secaudit - - - {message}"
    ).replace("\n", " ")
    data = line.encode("utf-8")
    if protocol == "udp":
        family = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0][0]
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(10.0)
            sock.sendto(data, (host, port))
        return

    with socket.create_connection((host, port), timeout=10.0) as raw:
        if protocol == "tls":
            ctx = ssl.create_default_context()
            if config.get("verify_tls") is False:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            with ctx.wrap_socket(raw, server_hostname=host) as tls_sock:
                tls_sock.sendall(data + b"\n")
        else:
            raw.sendall(data + b"\n")


def format_ecs(
    event: dict[str, Any],
    settings: SecAuditSettings,
    *,
    vendor: str = DEFAULT_VENDOR,
    product: str = DEFAULT_PRODUCT,
) -> dict[str, Any]:
    """Elastic Common Schema document for one audit or finding event."""
    outcome = str(event.get("outcome") or "success").lower()
    failed = outcome in {"failed", "failure", "denied"}
    action = str(event.get("action") or "")
    metadata = event.get("metadata") or {}
    finding = action.startswith("finding.")
    body: dict[str, Any] = {
        "@timestamp": event.get("timestamp"),
        "ecs": {"version": "8.11.0"},
        "message": metadata.get("message") or action,
        "event": {
            "kind": "alert" if finding else "event",
            "category": ["configuration"],
            "type": ["error"] if failed else ["info"],
            "action": action,
            "outcome": "failure" if failed else "success",
            "severity": cef_severity(event.get("severity"), outcome),
            "dataset": "secaudit.findings" if finding else "secaudit.audit",
            "id": None if event.get("id") is None else str(event.get("id")),
        },
        "rule": {"name": metadata.get("rule_tech_name") or event.get("resource_name")},
        "user": {"name": event.get("actor_username"), "roles": event.get("actor_roles") or []},
        "observer": {
            "vendor": vendor,
            "product": product,
            "version": settings.app_version,
            "type": "secaudit",
        },
        "secaudit": {
            "profile": metadata.get("profile"),
            "status": metadata.get("status"),
            "delta": metadata.get("delta"),
            "severity": event.get("severity"),
            "job_run_id": metadata.get("job_run_id"),
            "resource_type": event.get("resource_type"),
            "resource_id": event.get("resource_id"),
        },
    }
    if event.get("hostname"):
        body["host"] = {"name": event.get("hostname"), "id": metadata.get("host_id")}
    if event.get("ip_address"):
        body["source"] = {"ip": event.get("ip_address")}
    return body


def format_leef(
    event: dict[str, Any],
    settings: SecAuditSettings,
    *,
    vendor: str = DEFAULT_VENDOR,
    product: str = DEFAULT_PRODUCT,
) -> str:
    """LEEF 2.0 line. Attributes are tab-separated after the header."""
    metadata = event.get("metadata") or {}
    outcome = event.get("outcome")
    attrs = {
        "cat": event.get("resource_type"),
        "sev": cef_severity(event.get("severity"), outcome),
        "devTime": event.get("timestamp"),
        "identHostName": event.get("hostname"),
        "usrName": event.get("actor_username"),
        "resource": event.get("resource_name"),
        "outcome": outcome,
        "rule": metadata.get("rule_tech_name"),
        "status": metadata.get("status"),
        "delta": metadata.get("delta"),
        "profile": metadata.get("profile"),
        "severity": event.get("severity"),
        "src": event.get("ip_address"),
    }
    body = "\t".join(
        f"{key}={_cef_escape(value)}" for key, value in attrs.items() if value not in (None, "")
    )
    action = event.get("action") or "audit"
    return (
        f"LEEF:2.0|{_cef_escape(vendor)}|{_cef_escape(product)}|"
        f"{_cef_escape(settings.app_version)}|{_cef_escape(action)}|{body}"
    )


def _render_siem(fmt: str, event: dict[str, Any], settings: SecAuditSettings, vendor: str, product: str):
    if fmt == "cef":
        return "text", format_audit_cef(event, settings, vendor=vendor, product=product)
    if fmt == "leef":
        return "text", format_leef(event, settings, vendor=vendor, product=product)
    if fmt == "ecs":
        return "json", format_ecs(event, settings, vendor=vendor, product=product)
    return "json", format_audit_json(event, settings, vendor=vendor, product=product)


def deliver_siem_to_channel(
    channel: NotificationChannel,
    payload: dict[str, Any],
    settings: SecAuditSettings,
) -> None:
    from secaudit_core.url_safety import validate_outbound_webhook_url

    kind = "finding" if payload.get("finding") else "audit"
    audit_event = payload.get("finding") or payload.get("audit") or payload
    config = channel.config_json or {}
    vendor = str(config.get("vendor") or DEFAULT_VENDOR)
    product = str(config.get("product") or DEFAULT_PRODUCT)
    fmt = str(config.get("format") or "json").lower()
    kind_name, rendered = _render_siem(fmt, audit_event, settings, vendor, product)
    hostname = audit_event.get("hostname")
    severity = audit_event.get("severity")
    outcome = audit_event.get("outcome")

    if str(config.get("transport") or "").lower() == "syslog":
        message = rendered if kind_name == "text" else json.dumps(rendered, ensure_ascii=False, separators=(",", ":"))
        _deliver_syslog(config, message, settings, severity=severity, outcome=outcome, hostname=hostname)
        return

    url = _resolve_siem_url(channel, settings)
    if not url:
        raise ValueError("SIEM webhook URL is not configured")
    url = validate_outbound_webhook_url(
        url,
        allow_http=settings.app_env.strip().lower() != "production",
        allow_private=settings.outbound_webhooks_allow_private,
    )

    headers: dict[str, str] = {}
    if audit_event.get("id") is not None:
        headers["Idempotency-Key"] = f"secaudit-{kind}-{audit_event['id']}"
    extra = config.get("headers")
    if isinstance(extra, dict):
        headers.update({str(k): str(v) for k, v in extra.items()})

    if kind_name == "text":
        headers.setdefault("Content-Type", "text/plain; charset=utf-8")
        response = httpx.post(url, content=rendered, headers=headers, timeout=30.0, follow_redirects=False)
    else:
        headers.setdefault("Content-Type", "application/json")
        response = httpx.post(url, json=rendered, headers=headers, timeout=30.0, follow_redirects=False)
    response.raise_for_status()


def build_finding_siem_payload(
    *,
    job_run_id: int,
    job_id: int | None,
    job_name: str,
    action: str,
    outcome: str,
    trigger_events: list[str],
    counts: dict[str, int],
    detail: str | None = None,
    siem_modes: list[str] | None = None,
    finding_id: str | None = None,
    resource_type: str = "job_run",
    resource_id: str | None = None,
    resource_name: str | None = None,
    hostname: str | None = None,
    severity: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {"job_run_id": job_run_id, "job_id": job_id, **counts}
    if detail:
        metadata["detail"] = detail
    if extra:
        metadata.update(extra)
    return {
        "payload_type": "compliance",
        "siem_modes": siem_modes or ["summary"],
        "trigger_events": trigger_events,
        "finding": {
            "id": finding_id or f"{job_run_id}:{action}",
            "timestamp": datetime.now(UTC).isoformat(),
            "actor_username": "system",
            "actor_roles": ["system"],
            "action": action,
            "resource_type": resource_type,
            "resource_id": resource_id if resource_id is not None else str(job_run_id),
            "resource_name": resource_name or job_name,
            "outcome": outcome,
            "hostname": hostname,
            "severity": severity,
            "ip_address": None,
            "user_agent": None,
            "metadata": redact_sensitive(metadata),
        },
    }


def _active_siem_modes(db: Session) -> set[str]:
    rows = db.execute(
        select(NotificationChannel).where(
            NotificationChannel.channel_type == NotificationChannelType.SIEM,
            NotificationChannel.is_active.is_(True),
        )
    ).scalars().all()
    if not rows:
        return {"summary"}
    return {channel_siem_mode(row) for row in rows}


def _host_label(host: Host | None) -> str | None:
    if host is None:
        return None
    return (host.hostname or host.name or "").strip() or None


def _enqueue_check_findings(
    db: Session,
    *,
    job_run_id: int,
    job_id: int | None,
    job_name: str,
    counts: dict[str, int],
    want_findings: bool,
    want_delta: bool,
) -> None:
    current = list(
        db.execute(select(CheckResult).where(CheckResult.job_run_id == job_run_id)).scalars()
    )
    if not current:
        return
    previous: dict[tuple[int, str], str] = {}
    if job_id is not None:
        previous_run = db.execute(
            select(JobRun)
            .where(JobRun.job_id == job_id, JobRun.id < job_run_id)
            .order_by(JobRun.id.desc())
            .limit(1)
        ).scalar_one_or_none()
        if previous_run is not None:
            for row in db.execute(
                select(CheckResult).where(CheckResult.job_run_id == previous_run.id)
            ).scalars():
                previous[(row.host_id, row.rule_tech_name)] = _status_value(row.status)

    host_ids = {row.host_id for row in current}
    hosts = {
        host.id: host
        for host in db.execute(select(Host).where(Host.id.in_(host_ids))).scalars()
    } if host_ids else {}
    profile_name = ""
    severity_by_rule: dict[str, str] = {}
    if job_id is not None:
        job = db.get(Job, job_id)
        if job is not None and job.profile_id:
            profile = db.get(Profile, job.profile_id)
            profile_name = profile.profile_name if profile is not None else ""
            for rule in db.execute(select(Rule).where(Rule.profile_id == job.profile_id)).scalars():
                if rule.severity:
                    severity_by_rule[rule.tech_name] = str(rule.severity)

    for check in current:
        status = _status_value(check.status).lower()
        prior = previous.get((check.host_id, check.rule_tech_name))
        prior_bad = prior in {"fail", "error"}
        current_bad = status in {"fail", "error"}
        if prior_bad and status == "pass":
            action, delta, outcome, triggers = (
                "finding.resolved",
                "resolved",
                "success",
                [NotificationEventType.FINDING_RESOLVED.value],
            )
            modes = ["findings", "delta_only"]
        elif current_bad and prior == "pass":
            action, delta, outcome, triggers = (
                "finding.regressed",
                "regressed",
                "failed",
                [NotificationEventType.FINDING_REGRESSED.value],
            )
            modes = ["findings", "delta_only"]
        elif current_bad and prior is None:
            action, delta, outcome, triggers = (
                "finding.failed",
                "new",
                "failed",
                [NotificationEventType.FINDING_FAILED.value],
            )
            modes = ["findings", "delta_only"]
        elif current_bad:
            action, delta, outcome, triggers = (
                "finding.failed",
                "failed",
                "failed",
                [NotificationEventType.FINDING_FAILED.value],
            )
            modes = ["findings"]
        else:
            continue
        if "findings" in modes and not want_findings:
            modes = [mode for mode in modes if mode != "findings"]
        if "delta_only" in modes and not want_delta:
            modes = [mode for mode in modes if mode != "delta_only"]
        if not modes:
            continue
        hostname = _host_label(hosts.get(check.host_id))
        severity = severity_by_rule.get(check.rule_tech_name)
        message = (check.message or "")[:500]
        payload = build_finding_siem_payload(
            job_run_id=job_run_id,
            job_id=job_id,
            job_name=job_name,
            action=action,
            outcome=outcome,
            trigger_events=triggers,
            counts=counts,
            siem_modes=modes,
            finding_id=f"{job_run_id}:{check.id}:{action}",
            resource_type="check_result",
            resource_id=str(check.id),
            resource_name=check.rule_tech_name,
            hostname=hostname,
            severity=severity,
            extra={
                "host_id": check.host_id,
                "host_name": hosts[check.host_id].name if check.host_id in hosts else None,
                "hostname": hostname,
                "profile": profile_name,
                "rule_tech_name": check.rule_tech_name,
                "severity": severity,
                "status": status,
                "delta": delta,
                "message": message,
            },
        )
        enqueue_outbox_row(
            db,
            task_name="app.tasks.maintenance.send_notification",
            args=[payload],
            queue="maintenance",
            callback_kind="compliance_finding",
            callback_ref_id=job_run_id,
        )


def enqueue_compliance_siem_findings(
    db: Session,
    *,
    settings: SecAuditSettings,
    job_run_id: int,
    job_id: int | None,
    job_name: str,
    counts: dict[str, int],
    regressed_detail: str | None = None,
) -> None:
    """Queue finding SIEM events via TaskOutbox; caller commits."""
    if not settings.notifications_enabled:
        return
    modes = _active_siem_modes(db)
    if "summary" in modes:
        events: list[tuple[str, list[str], str | None]] = []
        if regressed_detail is not None:
            events.append(
                (
                    "finding.regressed",
                    [
                        NotificationEventType.COMPLIANCE_REGRESSED.value,
                        NotificationEventType.FINDING_REGRESSED.value,
                    ],
                    regressed_detail,
                )
            )
        if counts.get("fail_count"):
            events.append(("finding.failed", [NotificationEventType.FINDING_FAILED.value], None))
        for action, triggers, detail in events:
            payload = build_finding_siem_payload(
                job_run_id=job_run_id,
                job_id=job_id,
                job_name=job_name,
                action=action,
                outcome="failed",
                trigger_events=triggers,
                counts=counts,
                detail=detail,
                siem_modes=["summary"],
            )
            enqueue_outbox_row(
                db,
                task_name="app.tasks.maintenance.send_notification",
                args=[payload],
                queue="maintenance",
                callback_kind="compliance_finding",
                callback_ref_id=job_run_id,
            )
    if "findings" in modes or "delta_only" in modes:
        # shortcut: one outbox row per finding; batch if a single run exceeds tens of thousands.
        _enqueue_check_findings(
            db,
            job_run_id=job_run_id,
            job_id=job_id,
            job_name=job_name,
            counts=counts,
            want_findings="findings" in modes,
            want_delta="delta_only" in modes,
        )


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
