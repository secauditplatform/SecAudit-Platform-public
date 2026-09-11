"""Standalone console sandbox ASGI app (no DB, no remediation/API surface)."""

from __future__ import annotations

from fastapi import FastAPI, Query, WebSocket
from fastapi.responses import JSONResponse

from app.core.auth import resolve_ws_user
from app.core.config import settings
from app.services.console_session import run_console_session
from secaudit_core.enums import UserRole

app = FastAPI(title="SecAudit Console Sandbox", version=settings.app_version)


@app.get("/health")
@app.get("/health/live")
@app.get("/api/v1/health/live")
async def live() -> JSONResponse:
    return JSONResponse(
        {
            "status": "ok",
            "service": "console-sandbox",
            "console_enabled": settings.console_enabled_effective,
        }
    )


@app.websocket("/api/v1/ws/console")
async def console_ws(websocket: WebSocket, token: str | None = Query(default=None)) -> None:
    if not settings.console_enabled_effective:
        await websocket.close(code=4403, reason="Console disabled")
        return

    user = await resolve_ws_user(token)
    if not user or not user.has_role(UserRole.OPERATOR, UserRole.ADMIN):
        await websocket.close(code=4403, reason="Insufficient permissions")
        return

    await websocket.accept()
    await run_console_session(websocket, user=user)
