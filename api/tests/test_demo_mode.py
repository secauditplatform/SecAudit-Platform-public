"""Tests for demo-mode API guard."""

import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.testclient import TestClient

from app.middleware.demo_mode import DemoModeGuardMiddleware


def _app(enabled: bool) -> Starlette:
    async def ok(_request: Request) -> PlainTextResponse:
        return PlainTextResponse("ok")

    app = Starlette(routes=[])
    app.add_middleware(DemoModeGuardMiddleware, enabled=enabled)
    app.add_route("/api/v1/jobs", ok, methods=["GET", "POST"])
    app.add_route("/api/v1/auth/login", ok, methods=["POST"])
    app.add_route("/api/v1/profiles", ok, methods=["GET", "POST"])
    return app


def test_demo_mode_blocks_job_create() -> None:
    client = TestClient(_app(True))
    assert client.get("/api/v1/jobs").status_code == 200
    blocked = client.post("/api/v1/jobs")
    assert blocked.status_code == 403
    assert "Demo stand" in blocked.json()["detail"]


def test_demo_mode_allows_auth_login() -> None:
    client = TestClient(_app(True))
    assert client.post("/api/v1/auth/login").status_code == 200


def test_demo_mode_off_allows_writes() -> None:
    client = TestClient(_app(False))
    assert client.post("/api/v1/jobs").status_code == 200


@pytest.mark.asyncio
async def test_health_exposes_demo_mode(monkeypatch) -> None:
    from app.api.v1.routers import health as health_router
    from app.core.config import settings

    monkeypatch.setattr(settings, "demo_mode", True)
    response = await health_router.health_check()
    assert response.demo_mode is True
