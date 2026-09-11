from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import AuthUser, require_roles
from app.core.blocking import run_blocking
from app.core.config import settings
from app.core.database import get_db
from app.core.secrets import encrypt_secret
from app.models import NotificationChannel, UserRole
from app.schemas import (
    NotificationChannelCreate,
    NotificationChannelRead,
    NotificationChannelUpdate,
    NotificationTestResponse,
)
from app.services.audit_log import log_audit_event
from app.services.object_rbac import (
    apply_owner_scope,
    assert_can_access,
    assign_notification_channel_owner,
)
from secaudit_core.enums import NotificationChannelType
from secaudit_core.notifications import build_test_payload, deliver_to_channel
from secaudit_core.siem_export import build_siem_test_payload
from secaudit_core.sensitive_data import redact_sensitive

router = APIRouter()


def _channel_to_read(channel: NotificationChannel) -> NotificationChannelRead:
    return NotificationChannelRead(
        id=channel.id,
        name=channel.name,
        channel_type=channel.channel_type,
        is_active=channel.is_active,
        events=channel.events or [],
        config_json=redact_sensitive(channel.config_json),
        owner_sub=channel.owner_sub,
        has_secret=bool(channel.encrypted_secret),
        created_at=channel.created_at,
        updated_at=channel.updated_at,
    )


def _encrypt_channel_secret(secret: str | None) -> str | None:
    if not secret:
        return None
    return encrypt_secret(secret, settings)


@router.get("", response_model=list[NotificationChannelRead])
async def list_notification_channels(
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN, UserRole.OPERATOR)),
) -> list[NotificationChannelRead]:
    stmt = apply_owner_scope(
        select(NotificationChannel).order_by(NotificationChannel.name),
        NotificationChannel.owner_sub,
        user,
    )
    result = await db.execute(stmt)
    return [_channel_to_read(channel) for channel in result.scalars().all()]


@router.post("", response_model=NotificationChannelRead, status_code=201)
async def create_notification_channel(
    data: NotificationChannelCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN, UserRole.OPERATOR)),
) -> NotificationChannelRead:
    existing = await db.execute(select(NotificationChannel).where(NotificationChannel.name == data.name))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Notification channel with this name already exists")

    channel = NotificationChannel(
        name=data.name,
        channel_type=data.channel_type,
        is_active=data.is_active,
        events=[event.value if hasattr(event, "value") else str(event) for event in data.events],
        config_json=data.config_json,
        encrypted_secret=_encrypt_channel_secret(data.secret),
    )
    assign_notification_channel_owner(channel, user)
    db.add(channel)
    await db.flush()
    await db.refresh(channel)
    await log_audit_event(
        db,
        request,
        user,
        action="notification_channel.create",
        resource_type="notification_channel",
        resource_id=channel.id,
        resource_name=channel.name,
    )
    return _channel_to_read(channel)


@router.get("/{channel_id}", response_model=NotificationChannelRead)
async def get_notification_channel(
    channel_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN, UserRole.OPERATOR)),
) -> NotificationChannelRead:
    channel = await db.get(NotificationChannel, channel_id)
    if not channel:
        raise HTTPException(status_code=404, detail="Notification channel not found")
    assert_can_access(user, channel.owner_sub, detail="Notification channel not found")
    return _channel_to_read(channel)


@router.patch("/{channel_id}", response_model=NotificationChannelRead)
async def update_notification_channel(
    channel_id: int,
    data: NotificationChannelUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN, UserRole.OPERATOR)),
) -> NotificationChannelRead:
    channel = await db.get(NotificationChannel, channel_id)
    if not channel:
        raise HTTPException(status_code=404, detail="Notification channel not found")
    assert_can_access(user, channel.owner_sub, detail="Notification channel not found")

    if data.name is not None and data.name != channel.name:
        existing = await db.execute(select(NotificationChannel).where(NotificationChannel.name == data.name))
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Notification channel with this name already exists")
        channel.name = data.name

    if data.channel_type is not None:
        channel.channel_type = data.channel_type
    if data.is_active is not None:
        channel.is_active = data.is_active
    if data.events is not None:
        channel.events = [event.value if hasattr(event, "value") else str(event) for event in data.events]
    if data.config_json is not None:
        channel.config_json = data.config_json
    if data.secret:
        channel.encrypted_secret = _encrypt_channel_secret(data.secret)

    await db.flush()
    await db.refresh(channel)
    await log_audit_event(
        db,
        request,
        user,
        action="notification_channel.update",
        resource_type="notification_channel",
        resource_id=channel.id,
        resource_name=channel.name,
    )
    return _channel_to_read(channel)


@router.delete("/{channel_id}", status_code=204)
async def delete_notification_channel(
    channel_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN, UserRole.OPERATOR)),
) -> None:
    channel = await db.get(NotificationChannel, channel_id)
    if not channel:
        raise HTTPException(status_code=404, detail="Notification channel not found")
    assert_can_access(user, channel.owner_sub, detail="Notification channel not found")

    channel_name = channel.name
    await db.delete(channel)
    await log_audit_event(
        db,
        request,
        user,
        action="notification_channel.delete",
        resource_type="notification_channel",
        resource_id=channel_id,
        resource_name=channel_name,
    )


@router.post("/{channel_id}/test", response_model=NotificationTestResponse)
async def test_notification_channel(
    channel_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN, UserRole.OPERATOR)),
) -> NotificationTestResponse:
    channel = await db.get(NotificationChannel, channel_id)
    if not channel:
        raise HTTPException(status_code=404, detail="Notification channel not found")
    assert_can_access(user, channel.owner_sub, detail="Notification channel not found")

    if channel.channel_type == NotificationChannelType.SIEM:
        payload = build_siem_test_payload(settings)
        payload["trigger_events"] = channel.events or payload["trigger_events"]
        try:
            from secaudit_core.siem_export import deliver_siem_to_channel

            await run_blocking(
                deliver_siem_to_channel,
                channel,
                payload,
                settings,
                timeout=settings.blocking_io_timeout_seconds,
            )
            result = {"sent": 1, "skipped": 0, "errors": []}
        except Exception as exc:
            result = {
                "sent": 0,
                "skipped": 0,
                "errors": [redact_sensitive(str(exc))],
            }
    else:
        payload = build_test_payload(settings)
        payload["trigger_events"] = channel.events or payload["trigger_events"]
        try:
            await run_blocking(
                deliver_to_channel,
                channel,
                payload,
                settings,
                timeout=settings.blocking_io_timeout_seconds,
            )
            result = {"sent": 1, "skipped": 0, "errors": []}
        except Exception as exc:
            result = {
                "sent": 0,
                "skipped": 0,
                "errors": [redact_sensitive(str(exc))],
            }

    await log_audit_event(
        db,
        request,
        user,
        action="notification_channel.test",
        resource_type="notification_channel",
        resource_id=channel.id,
        resource_name=channel.name,
        outcome="success" if not result["errors"] else "failed",
        metadata={"errors": result["errors"]},
    )
    return NotificationTestResponse(**result)
