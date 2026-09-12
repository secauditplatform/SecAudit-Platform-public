"""Standalone console sandbox ASGI app (no DB, no remediation/API surface)."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket
from fastapi.responses import JSONResponse

from app.core.auth import authenticate_websocket
from app.core.config import settings
from app.services.console_session import run_console_session
from secaudit_core.enums import UserRole
from secaudit_core.security import (
    validate_production_runtime_config,
    validate_production_secret_key,
)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Console verifies JWTs only; still refuse insecure production posture.
    signing_key = settings.local_jwt_signing_key_effective
    validate_production_secret_key(signing_key, settings.app_env)
    validate_production_runtime_config(
        app_env=settings.app_env,
        auth_enabled=settings.auth_enabled,
        api_debug=False,
        object_rbac_enabled=True,
    )
    yield


app = FastAPI(
    title="SecAudit Console Sandbox",
    version=settings.app_version,
    lifespan=lifespan,
)


@app.get("/health")
@app.get("/health/live")
@app.get("/api/v1/health/live")
async def live() -> JSONResponse:
    return JSONResponse(
        {
            "status": "ok",
            "service": "console-sandbox",
            "console_enabled": settings.console_enabled_effective,
            "demo_mode": settings.demo_mode,
        }
    )


@app.websocket("/api/v1/ws/console")
async def console_ws(websocket: WebSocket) -> None:
    if not settings.console_enabled_effective:
        await websocket.close(code=4403, reason="Console disabled")
        return

    # Auth via first JSON frame (same as API console) — never query-string tokens.
    user, _token = await authenticate_websocket(websocket)
    if not user or not user.has_role(UserRole.OPERATOR, UserRole.ADMIN):
        await websocket.close(code=4403, reason="Insufficient permissions")
        return

    await run_console_session(websocket, user=user)
