"""Standalone console sandbox ASGI app (no DB, no remediation/API surface)."""

from __future__ import annotations

from fastapi import FastAPI, WebSocket
from fastapi.responses import JSONResponse

from app.core.auth import resolve_ws_user
from app.core.config import settings
from app.services.console_session import run_console_session
from secaudit_core.enums import UserRole

app = FastAPI(title="SecAudit Console Sandbox", version=settings.app_version)


def _bearer_token(websocket: WebSocket) -> str | None:
    """Read the JWT from the Authorization header. Query tokens are ignored."""
    header = websocket.headers.get("authorization")
    if not header:
        return None
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer":
        return None
    token = value.strip()
    return token or None


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
async def console_ws(websocket: WebSocket) -> None:
    if not settings.console_enabled_effective:
        await websocket.close(code=4403, reason="Console disabled")
        return

    # Sandbox image has no asyncpg/Postgres. API already authenticated + revoked.
    # The proxy sends the JWT as a header so it does not land in the access log URL.
    user = await resolve_ws_user(_bearer_token(websocket), live_revalidate=False)
    if not user or not user.has_role(UserRole.OPERATOR, UserRole.ADMIN):
        await websocket.close(code=4403, reason="Insufficient permissions")
        return

    await websocket.accept()
    await run_console_session(websocket, user=user)
