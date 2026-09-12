import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import AuthUser, authenticate_websocket
from app.core.roles import require_operate
from app.core.config import settings
from app.core.database import get_db
from app.schemas import AuditFlowLogEntry, JobRunLogEntry, RemediationRunLogEntry
from app.services.console_proxy import proxy_console_websocket
from app.services.console_session import run_console_session
from app.services.object_rbac import (
    assert_audit_flow_run_access,
    assert_job_run_access,
    assert_remediation_run_access,
)
from secaudit_core.enums import UserRole
from secaudit_core.redis_client import async_redis

router = APIRouter()


def _ws_user_can_operate(user: AuthUser) -> bool:
    return user.has_role(UserRole.OPERATOR, UserRole.ADMIN)


async def _reject_demo_execute_ws(websocket: WebSocket) -> bool:
    """Return True if the socket was closed because demo mode blocks execute streams."""
    if not settings.demo_mode:
        return False
    await websocket.close(code=4403, reason="Demo mode: execute streams disabled")
    return True


@router.get("/job-runs/{run_id}/logs", response_model=list[JobRunLogEntry])
async def get_job_run_logs(
    run_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_operate),
) -> list[JobRunLogEntry]:
    await assert_job_run_access(db, user, run_id)
    client = async_redis(settings.redis_url, settings=settings)
    try:
        raw = await client.lrange(f"job_run_logs:{run_id}", 0, 499)
        entries = [JobRunLogEntry(**json.loads(item)) for item in reversed(raw)]
        return entries
    finally:
        await client.aclose()


@router.websocket("/job-runs/{run_id}")
async def job_run_logs_ws(
    websocket: WebSocket,
    run_id: int,
) -> None:
    user, _token = await authenticate_websocket(websocket)
    if not user:
        await websocket.close(code=4401, reason="Not authenticated")
        return
    if not _ws_user_can_operate(user):
        await websocket.close(code=4403, reason="Insufficient permissions")
        return
    if await _reject_demo_execute_ws(websocket):
        return

    from app.core.database import async_session

    async with async_session() as db:
        try:
            await assert_job_run_access(db, user, run_id)
        except HTTPException:
            await websocket.close(code=4404, reason="Job run not found")
            return

    client = async_redis(settings.redis_url, settings=settings)
    pubsub = client.pubsub()
    channel = f"job_run:{run_id}"

    try:
        cached = await client.lrange(f"job_run_logs:{run_id}", 0, 99)
        for item in reversed(cached):
            await websocket.send_text(item)

        await pubsub.subscribe(channel)
        while True:
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if message and message.get("type") == "message":
                await websocket.send_text(message["data"])
            await asyncio.sleep(0.05)
    except WebSocketDisconnect:
        pass
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.aclose()
        await client.aclose()


@router.get("/remediation-runs/{run_id}/logs", response_model=list[RemediationRunLogEntry])
async def get_remediation_run_logs(
    run_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_operate),
) -> list[RemediationRunLogEntry]:
    await assert_remediation_run_access(db, user, run_id)
    client = async_redis(settings.redis_url, settings=settings)
    try:
        raw = await client.lrange(f"remediation_run_logs:{run_id}", 0, 499)
        entries = [RemediationRunLogEntry(**json.loads(item)) for item in reversed(raw)]
        return entries
    finally:
        await client.aclose()


@router.websocket("/remediation-runs/{run_id}")
async def remediation_run_logs_ws(
    websocket: WebSocket,
    run_id: int,
) -> None:
    user, _token = await authenticate_websocket(websocket)
    if not user:
        await websocket.close(code=4401, reason="Not authenticated")
        return
    if not _ws_user_can_operate(user):
        await websocket.close(code=4403, reason="Insufficient permissions")
        return
    if await _reject_demo_execute_ws(websocket):
        return

    from app.core.database import async_session

    async with async_session() as db:
        try:
            await assert_remediation_run_access(db, user, run_id)
        except HTTPException:
            await websocket.close(code=4404, reason="Remediation run not found")
            return

    client = async_redis(settings.redis_url, settings=settings)
    pubsub = client.pubsub()
    channel = f"remediation_run:{run_id}"

    try:
        cached = await client.lrange(f"remediation_run_logs:{run_id}", 0, 99)
        for item in reversed(cached):
            await websocket.send_text(item)

        await pubsub.subscribe(channel)
        while True:
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if message and message.get("type") == "message":
                await websocket.send_text(message["data"])
            await asyncio.sleep(0.05)
    except WebSocketDisconnect:
        pass
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.aclose()
        await client.aclose()


@router.get("/audit-flow/{run_id}/logs", response_model=list[AuditFlowLogEntry])
async def get_audit_flow_logs(
    run_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_operate),
) -> list[AuditFlowLogEntry]:
    await assert_audit_flow_run_access(db, user, run_id)
    client = async_redis(settings.redis_url, settings=settings)
    try:
        raw = await client.lrange(f"audit_flow_run_logs:{run_id}", 0, 499)
        return [AuditFlowLogEntry(**json.loads(item)) for item in reversed(raw)]
    finally:
        await client.aclose()


@router.websocket("/audit-flow/{run_id}")
async def audit_flow_logs_ws(
    websocket: WebSocket,
    run_id: int,
) -> None:
    user, _token = await authenticate_websocket(websocket)
    if not user:
        await websocket.close(code=4401, reason="Not authenticated")
        return
    if not _ws_user_can_operate(user):
        await websocket.close(code=4403, reason="Insufficient permissions")
        return
    if await _reject_demo_execute_ws(websocket):
        return

    from app.core.database import async_session

    async with async_session() as db:
        try:
            await assert_audit_flow_run_access(db, user, run_id)
        except HTTPException:
            await websocket.close(code=4404, reason="AuditFlow run not found")
            return

    client = async_redis(settings.redis_url, settings=settings)
    pubsub = client.pubsub()
    channel = f"audit_flow_run:{run_id}"

    try:
        cached = await client.lrange(f"audit_flow_run_logs:{run_id}", 0, 99)
        for item in reversed(cached):
            await websocket.send_text(item)

        await pubsub.subscribe(channel)
        while True:
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
            if message and message.get("type") == "message":
                await websocket.send_text(message["data"])
            await asyncio.sleep(0.05)
    except WebSocketDisconnect:
        pass
    finally:
        await pubsub.unsubscribe(channel)
        await pubsub.aclose()
        await client.aclose()


@router.websocket("/console")
async def console_ws(websocket: WebSocket) -> None:
    if not settings.console_enabled_effective:
        await websocket.close(code=4403, reason="Console disabled")
        return

    user, token = await authenticate_websocket(websocket)
    if not user or not user.has_role(UserRole.OPERATOR, UserRole.ADMIN):
        await websocket.close(code=4403, reason="Insufficient permissions")
        return

    if settings.console_sandbox_enabled_effective:
        await proxy_console_websocket(
            websocket,
            sandbox_url=settings.console_sandbox_url or "",
            token=token,
        )
        return

    await run_console_session(websocket, user=user)
