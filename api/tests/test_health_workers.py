"""Health readiness checks for worker heartbeat age."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.schemas import ComponentHealth
from app.services import health_checks


def test_check_celery_workers_reports_stale_heartbeat():
    mock_app = MagicMock()
    mock_app.control.inspect.return_value.ping.return_value = {"worker1": "pong"}
    with patch("app.services.health_checks.create_celery_app", return_value=mock_app):
        with patch(
            "app.services.health_checks.worker_heartbeat_age_seconds",
            return_value=250.0,
        ):
            with patch.object(health_checks.settings, "readiness_redact_details", False):
                result = health_checks._check_celery_workers_sync()
    assert result.status == "error"
    assert "heartbeat stale" in (result.detail or "")


def test_check_celery_workers_ok_when_heartbeat_fresh():
    mock_app = MagicMock()
    mock_app.control.inspect.return_value.ping.return_value = {"worker1": "pong"}
    with patch("app.services.health_checks.create_celery_app", return_value=mock_app):
        with patch(
            "app.services.health_checks.worker_heartbeat_age_seconds",
            return_value=12.0,
        ):
            with patch.object(health_checks.settings, "readiness_redact_details", False):
                result = health_checks._check_celery_workers_sync()
    assert result.status == "ok"
    assert "heartbeat 12s ago" in (result.detail or "")


def test_health_ready_all_ok(client: TestClient):
    ok = ComponentHealth(status="ok")
    components = {"postgres": ok, "redis": ok, "celery_broker": ok, "celery_workers": ok}
    with patch(
        "app.api.v1.routers.health.gather_readiness_components",
        new=AsyncMock(return_value=components),
    ):
        response = client.get("/api/v1/health/ready")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
