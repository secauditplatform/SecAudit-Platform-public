"""Scheduled compliance report delivery (email / S3)."""

from __future__ import annotations

import logging
import smtplib
from datetime import UTC, datetime, timedelta
from email.message import EmailMessage
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from secaudit_core.enums import JobStatus, ScheduledReportDelivery, ScheduledReportFormat
from secaudit_core.models import JobRun, ScheduledReport, ScheduledReportDeliveryAttempt
from secaudit_core.reports import (
    fetch_run_report_context_sync,
    render_run_report_html,
    render_run_report_pdf,
)
from secaudit_core.secrets import decrypt_secret
from secaudit_core.settings import SecAuditSettings
from secaudit_core.storage import upload_report_object

logger = logging.getLogger(__name__)

ReportAttachment = tuple[str, bytes, str]
CLAIM_STALE_AFTER = timedelta(minutes=30)


def find_latest_completed_run(db: Session, job_id: int) -> JobRun | None:
    return db.execute(
        select(JobRun)
        .where(JobRun.job_id == job_id, JobRun.status == JobStatus.COMPLETED)
        .order_by(JobRun.finished_at.desc().nullslast(), JobRun.id.desc())
        .limit(1)
    ).scalar_one_or_none()


def build_report_attachments(
    job_run: JobRun,
    profile,
    hosts: dict,
    report_format: ScheduledReportFormat | str,
    *,
    locale: str | None = None,
) -> list[ReportAttachment]:
    fmt = report_format.value if hasattr(report_format, "value") else str(report_format)
    base_name = f"secaudit-report-run-{job_run.id}"
    attachments: list[ReportAttachment] = []

    if fmt in {ScheduledReportFormat.HTML.value, ScheduledReportFormat.BOTH.value}:
        html = render_run_report_html(job_run, profile, hosts, for_pdf=False, locale=locale)
        attachments.append((f"{base_name}.html", html.encode("utf-8"), "text/html; charset=utf-8"))

    if fmt in {ScheduledReportFormat.PDF.value, ScheduledReportFormat.BOTH.value}:
        pdf = render_run_report_pdf(job_run, profile, hosts, locale=locale)
        attachments.append((f"{base_name}.pdf", pdf, "application/pdf"))

    return attachments


def _resolve_smtp_password(schedule: ScheduledReport, settings: SecAuditSettings) -> str | None:
    config = schedule.config_json or {}
    if schedule.encrypted_secret:
        return decrypt_secret(schedule.encrypted_secret, settings)
    if config.get("smtp_password"):
        return str(config["smtp_password"])
    return settings.smtp_password


def _normalize_recipients(raw: object) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        return [part.strip() for part in raw.split(",") if part.strip()]
    if isinstance(raw, (list, tuple, set)):
        out: list[str] = []
        for item in raw:
            text = str(item).strip()
            if text:
                out.append(text)
        return out
    return []


def _send_report_email(
    schedule: ScheduledReport,
    *,
    job_run: JobRun,
    job_name: str,
    attachments: list[ReportAttachment],
    settings: SecAuditSettings,
) -> None:
    config = schedule.config_json or {}
    recipients = _normalize_recipients(config.get("to_addresses"))
    if not recipients:
        raise ValueError("Email delivery requires at least one recipient in to_addresses")

    smtp_host = (config.get("smtp_host") or settings.smtp_host or "").strip()
    if not smtp_host:
        raise ValueError(
            "SMTP host is not configured. Set SMTP_HOST in .env "
            "(local Mailpit: mailpit:1025) or smtp_host in the schedule config."
        )

    smtp_port = int(config.get("smtp_port") or settings.smtp_port or 587)
    smtp_user = config.get("smtp_user") or settings.smtp_user
    smtp_password = _resolve_smtp_password(schedule, settings)
    from_address = config.get("from_address") or settings.smtp_from or smtp_user
    if not from_address:
        raise ValueError("SMTP from address is not configured (SMTP_FROM / from_address)")

    subject = f"SecAudit scheduled report — {job_name} (run #{job_run.id})"
    body = "\n".join(
        [
            f"Scheduled report: {schedule.name}",
            f"Job: {job_name}",
            f"Run: #{job_run.id}",
            f"Status: {job_run.status.value}",
            "",
            f"Attachments: {', '.join(name for name, _, _ in attachments)}",
        ]
    )

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = from_address
    message["To"] = ", ".join(recipients)
    message.set_content(body)

    for filename, content, mime_type in attachments:
        maintype, _, subtype = mime_type.partition("/")
        message.add_attachment(
            content,
            maintype=maintype,
            subtype=subtype or "octet-stream",
            filename=filename,
        )

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
            raise ValueError("SMTP user is set but password is missing (SMTP_PASSWORD / schedule secret)")
        smtp.send_message(message)


def _deterministic_s3_key(
    schedule: ScheduledReport,
    *,
    job_run: JobRun,
    filename: str,
    prefix: str,
) -> str:
    """Stable object key so retries overwrite instead of creating duplicates."""
    key_parts = [
        part
        for part in (
            prefix,
            f"schedule-{schedule.id}",
            f"run-{job_run.id}",
            filename,
        )
        if part
    ]
    return "/".join(key_parts)


def _deliver_report_s3(
    schedule: ScheduledReport,
    *,
    job_run: JobRun,
    attachments: list[ReportAttachment],
    settings: SecAuditSettings,
) -> list[str]:
    config = schedule.config_json or {}
    bucket = config.get("bucket") or settings.s3_bucket
    access_key = config.get("access_key") or settings.s3_access_key
    secret_key = None
    if schedule.encrypted_secret:
        secret_key = decrypt_secret(schedule.encrypted_secret, settings)
    else:
        secret_key = config.get("secret_key") or settings.s3_secret_key

    endpoint_url = config.get("endpoint_url") or settings.s3_endpoint_url
    prefix = str(config.get("prefix") or settings.s3_prefix or "").strip("/")
    uploaded: list[str] = []

    for filename, content, mime_type in attachments:
        object_key = _deterministic_s3_key(
            schedule, job_run=job_run, filename=filename, prefix=prefix
        )
        location = upload_report_object(
            settings=settings,
            key=object_key,
            content=content,
            content_type=mime_type,
            bucket=bucket,
            access_key=access_key,
            secret_key=secret_key,
            endpoint_url=endpoint_url,
        )
        uploaded.append(location)

    return uploaded


def build_delivery_key(schedule: ScheduledReport, job_run: JobRun, now: datetime) -> str:
    """Unique key for one schedule/run/cron-window delivery attempt."""
    from croniter import croniter

    try:
        cron = croniter(schedule.cron_expression, now)
        prev_run = cron.get_prev(datetime)
        if prev_run.tzinfo is None:
            prev_run = prev_run.replace(tzinfo=UTC)
        window = prev_run.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")
    except (ValueError, KeyError):
        window = "manual"
    return f"{schedule.id}:run-{job_run.id}:window-{window}"


def _claim_delivery(
    db: Session,
    schedule: ScheduledReport,
    job_run: JobRun,
    delivery_key: str,
) -> ScheduledReportDeliveryAttempt | None:
    """Insert a durable delivery claim. Returns None if already claimed/delivered."""
    existing = db.execute(
        select(ScheduledReportDeliveryAttempt).where(
            ScheduledReportDeliveryAttempt.schedule_id == schedule.id,
            ScheduledReportDeliveryAttempt.delivery_key == delivery_key,
        )
    ).scalar_one_or_none()
    if existing is not None:
        if existing.status == "delivered":
            return None
        if existing.status == "claimed":
            created = existing.created_at
            if created is not None and created.tzinfo is None:
                created = created.replace(tzinfo=UTC)
            if created is not None and datetime.now(UTC) - created < CLAIM_STALE_AFTER:
                return None
        # Failed or stale claimed attempts may be retried once.
        existing.status = "claimed"
        existing.error_message = None
        existing.completed_at = None
        existing.job_run_id = job_run.id
        db.flush()
        return existing

    attempt = ScheduledReportDeliveryAttempt(
        schedule_id=schedule.id,
        delivery_key=delivery_key,
        job_run_id=job_run.id,
        status="claimed",
    )
    try:
        with db.begin_nested():
            db.add(attempt)
            db.flush()
    except IntegrityError:
        return None
    return attempt


def deliver_scheduled_report(
    db: Session,
    schedule: ScheduledReport,
    settings: SecAuditSettings,
    *,
    run_id: int | None = None,
    now: datetime | None = None,
    manual: bool = False,
) -> dict[str, Any]:
    if not settings.scheduled_reports_enabled:
        return {"delivered": False, "reason": "scheduled_reports_disabled"}

    now = now or datetime.now(UTC)
    target_run_id = run_id
    job_run: JobRun | None = None
    if target_run_id is not None:
        job_run = db.get(JobRun, target_run_id)
        if not job_run or job_run.job_id != schedule.job_id:
            return {"delivered": False, "reason": "run_not_found"}
        if job_run.status != JobStatus.COMPLETED:
            return {"delivered": False, "reason": "run_not_completed"}
    else:
        job_run = find_latest_completed_run(db, schedule.job_id)
        if not job_run:
            return {"delivered": False, "reason": "no_completed_runs"}

    if manual:
        # "Send now" must not collide with the cron delivery window claim.
        delivery_key = f"{schedule.id}:run-{job_run.id}:manual-{now.strftime('%Y%m%dT%H%M%S%fZ')}"
    else:
        delivery_key = build_delivery_key(schedule, job_run, now)
    attempt = _claim_delivery(db, schedule, job_run, delivery_key)
    if attempt is None:
        return {
            "delivered": False,
            "reason": "already_delivered_or_in_progress",
            "delivery_key": delivery_key,
            "run_id": job_run.id,
        }

    # Persist the claim before external I/O so a crash after send cannot re-claim.
    db.commit()
    db.refresh(attempt)
    db.refresh(schedule)

    context = fetch_run_report_context_sync(db, job_run.id)
    if not context:
        attempt.status = "failed"
        attempt.error_message = "report_context_unavailable"
        attempt.completed_at = datetime.now(UTC)
        db.commit()
        return {"delivered": False, "reason": "report_context_unavailable"}

    _, profile, hosts = context
    job_name = job_run.job.name if job_run.job else f"Job #{schedule.job_id}"
    schedule_locale = (schedule.config_json or {}).get("locale")
    locale_code = str(schedule_locale).strip() if schedule_locale else ""
    attachments = build_report_attachments(
        job_run,
        profile,
        hosts,
        schedule.report_format,
        locale=locale_code or None,
    )
    if not attachments:
        attempt.status = "failed"
        attempt.error_message = "no_attachments"
        attempt.completed_at = datetime.now(UTC)
        db.commit()
        return {"delivered": False, "reason": "no_attachments"}

    try:
        if schedule.delivery_type == ScheduledReportDelivery.EMAIL:
            _send_report_email(
                schedule,
                job_run=job_run,
                job_name=job_name,
                attachments=attachments,
                settings=settings,
            )
            locations: list[str] = []
        elif schedule.delivery_type == ScheduledReportDelivery.S3:
            locations = _deliver_report_s3(
                schedule,
                job_run=job_run,
                attachments=attachments,
                settings=settings,
            )
        else:
            raise ValueError(f"Unsupported delivery type: {schedule.delivery_type}")
    except Exception as exc:
        attempt.status = "failed"
        attempt.error_message = str(exc)[:2000]
        attempt.completed_at = datetime.now(UTC)
        db.commit()
        raise

    delivered_at = datetime.now(UTC)
    attempt.status = "delivered"
    attempt.completed_at = delivered_at
    attempt.error_message = None
    schedule.last_delivered_at = delivered_at
    schedule.last_delivered_run_id = job_run.id
    # Commit success before returning so a crash cannot leave a "claimed" row
    # after external delivery already happened.
    db.commit()

    return {
        "delivered": True,
        "run_id": job_run.id,
        "delivery_type": schedule.delivery_type.value,
        "attachments": [name for name, _, _ in attachments],
        "locations": locations,
        "delivered_at": delivered_at.isoformat(),
        "delivery_key": delivery_key,
    }


def should_trigger_schedule(schedule: ScheduledReport, now: datetime) -> bool:
    from croniter import croniter

    try:
        cron = croniter(schedule.cron_expression, now)
        prev_run = cron.get_prev(datetime)
    except (ValueError, KeyError):
        return False

    if schedule.last_delivered_at is None:
        return True

    last = schedule.last_delivered_at
    if last.tzinfo is None:
        last = last.replace(tzinfo=UTC)
    return prev_run > last
