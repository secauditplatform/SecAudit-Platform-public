from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.schemas import ComponentHealth


def test_health_live_returns_ok(client: TestClient):
    response = client.get("/api/v1/health/live")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "app_name" in data


def test_health_root_returns_ok(client: TestClient):
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_health_ready_all_ok(client: TestClient):
    ok = ComponentHealth(status="ok")
    components = {"postgres": ok, "redis": ok, "celery_broker": ok, "celery_workers": ok}
    with patch(
        "app.api.v1.routers.health.gather_readiness_components",
        new=AsyncMock(return_value=components),
    ):
        response = client.get("/api/v1/health/ready")

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["components"]["postgres"]["status"] == "ok"
    assert data["components"]["redis"]["status"] == "ok"
    assert data["components"]["celery_broker"]["status"] == "ok"
    assert data["components"]["celery_workers"]["status"] == "ok"


def test_health_ready_returns_503_when_dependency_down(client: TestClient):
    components = {
        "postgres": ComponentHealth(status="ok"),
        "redis": ComponentHealth(status="error", detail="dependency unavailable"),
        "celery_broker": ComponentHealth(status="ok"),
        "celery_workers": ComponentHealth(status="ok"),
    }
    with patch(
        "app.api.v1.routers.health.gather_readiness_components",
        new=AsyncMock(return_value=components),
    ):
        response = client.get("/api/v1/health/ready")

    assert response.status_code == 503
    data = response.json()
    assert data["status"] == "error"
    assert data["components"]["redis"]["detail"] == "dependency unavailable"
