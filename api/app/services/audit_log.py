import logging
import json
from collections.abc import Mapping
from typing import Any

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import AuthUser
from app.core.config import settings
from app.core.database import async_session
from app.models import AuditLog, TaskOutbox
from secaudit_core.enums import OutboxStatus
from secaudit_core.siem_export import audit_log_to_dict, build_audit_siem_payload
from secaudit_core.sensitive_data import redact_sensitive
from secaudit_core.task_outbox import deterministic_task_id

logger = logging.getLogger(__name__)


def _request_ip(request: Request | None) -> str | None:
    if request is None:
        return None
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip() or None
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip() or None
    if request.client:
        return request.client.host
    return None


def _resolve_actor(user: AuthUser | None) -> tuple[str, list[str] | None, str]:
    if user is None:
        return "anonymous", None, "anonymous"
    username = user.username.strip() if isinstance(user.username, str) else ""
    if not username:
        username = user.sub or "unknown"
    auth_mode = user.auth_mode if getattr(user, "auth_mode", None) else "unknown"
    return username, user.roles, auth_mode


def _build_audit_event(
    request: Request | None,
    user: AuthUser | None,
    action: str,
    resource_type: str,
    resource_id: int | str | None,
    resource_name: str | None,
    outcome: str,
    metadata: Mapping[str, Any] | None,
) -> AuditLog:
    actor_username, actor_roles, auth_mode = _resolve_actor(user)
    payload = {
        "auth_mode": auth_mode,
        "subject": user.sub if user else None,
    }
    if metadata:
        payload.update(redact_sensitive(dict(metadata)))
    return AuditLog(
        actor_username=actor_username,
        actor_roles=actor_roles,
        action=action,
        resource_type=resource_type,
        resource_id=None if resource_id is None else str(resource_id),
        resource_name=resource_name,
        outcome=outcome,
        ip_address=_request_ip(request),
        user_agent=request.headers.get("user-agent") if request else None,
        metadata_json=payload,
    )


async def log_audit_event(
    db: AsyncSession | None,
    request: Request | None,
    user: AuthUser | None,
    action: str,
    resource_type: str,
    resource_id: int | str | None = None,
    resource_name: str | None = None,
    outcome: str = "success",
    metadata: Mapping[str, Any] | None = None,
    durable: bool = False,
) -> None:
    """Persist audit and SIEM publication intent in one transaction."""
    event = _build_audit_event(
        request,
        user,
        action,
        resource_type,
        resource_id,
        resource_name,
        outcome,
        metadata,
    )

    async def _add_event_and_outbox(session: AsyncSession) -> None:
        session.add(event)
        await session.flush()
        if settings.notifications_enabled:
            payload = build_audit_siem_payload(audit_event=audit_log_to_dict(event))
            outbox = TaskOutbox(
                task_name="app.tasks.maintenance.send_notification",
                args_json=json.dumps([payload]),
                kwargs_json="{}",
                queue="maintenance",
                status=OutboxStatus.PENDING,
                callback_kind="audit_log",
                callback_ref_id=event.id,
            )
            session.add(outbox)
            await session.flush()
            outbox.celery_task_id = deterministic_task_id(outbox.id)

    if db is not None and not durable:
        await _add_event_and_outbox(db)
        return

    try:
        async with async_session() as audit_db:
            await _add_event_and_outbox(audit_db)
            await audit_db.commit()
    except Exception:
        logger.critical(
            "Failed to durably persist security audit event action=%s outcome=%s",
            action,
            outcome,
            exc_info=True,
        )
        raise
