"""P2 API: migration indexes, stamp fail-closed, health/metrics hardening."""

from __future__ import annotations

import os
import uuid
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError

from app.main import _run_alembic_upgrade, _validate_legacy_baseline, app
from app.schemas import ComponentHealth


def _postgres_url(database: str) -> str:
    user = os.environ.get("POSTGRES_USER", "secaudit")
    password = os.environ.get("POSTGRES_PASSWORD", "secaudit_dev")
    host = os.environ.get("POSTGRES_HOST", "localhost")
    port = os.environ.get("POSTGRES_PORT", "5432")
    return f"postgresql://{user}:{password}@{host}:{port}/{database}"


@pytest.fixture
def disposable_pg_database():
    admin = create_engine(_postgres_url("postgres"), isolation_level="AUTOCOMMIT")
    db_name = f"secaudit_mig028_{uuid.uuid4().hex[:8]}"
    try:
        with admin.connect() as conn:
            conn.execute(text(f'CREATE DATABASE "{db_name}"'))
    except OperationalError as exc:
        admin.dispose()
        pytest.skip(f"PostgreSQL is not available for migration tests: {exc}")

    engine = create_engine(_postgres_url(db_name))
    try:
        yield engine, db_name
    finally:
        engine.dispose()
        with admin.connect() as conn:
            conn.execute(
                text(
                    """
                    SELECT pg_terminate_backend(pid)
                    FROM pg_stat_activity
                    WHERE datname = :db_name AND pid <> pg_backend_pid()
                    """
                ),
                {"db_name": db_name},
            )
            conn.execute(text(f'DROP DATABASE IF EXISTS "{db_name}"'))
        admin.dispose()


def test_028_creates_fk_indexes_and_delivery_attempts(disposable_pg_database):
    _engine, db_name = disposable_pg_database
    alembic_ini = Path(__file__).resolve().parents[1] / "alembic.ini"
    cfg = Config(str(alembic_ini))
    cfg.set_main_option("sqlalchemy.url", _postgres_url(db_name))

    command.upgrade(cfg, "head")

    with _engine.connect() as conn:
        indexes = {
            row[0]
            for row in conn.execute(
                text(
                    """
                    SELECT indexname FROM pg_indexes
                    WHERE schemaname = 'public'
                      AND indexname LIKE 'ix_%'
                    """
                )
            )
        }
        assert "ix_job_runs_job_id" in indexes
        assert "ix_job_runs_job_id_created_at" in indexes
        assert "ix_check_results_job_run_id" in indexes
        assert "ix_check_results_host_id" in indexes
        assert "ix_remediation_runs_remediation_job_id" in indexes
        assert "ix_remediation_results_host_id" in indexes

        tables = {
            row[0]
            for row in conn.execute(
                text(
                    """
                    SELECT tablename FROM pg_tables
                    WHERE schemaname = 'public'
                    """
                )
            )
        }
        assert "scheduled_report_delivery_attempts" in tables


def test_legacy_stamp_fails_closed_without_flag(monkeypatch):
    monkeypatch.delenv("ALLOW_LEGACY_ALEMBIC_STAMP", raising=False)
    monkeypatch.delenv("SKIP_MIGRATIONS", raising=False)

    class _Inspector:
        def get_table_names(self):
            return ["jobs", "hosts"]

    @contextmanager
    def fake_lock(_url):
        yield

    monkeypatch.setattr("app.main._migration_advisory_lock", fake_lock)
    with patch("app.main.create_engine") as mock_engine_factory:
        mock_engine_factory.return_value.dispose = lambda: None
        with patch("app.main.inspect", return_value=_Inspector()):
            with pytest.raises(RuntimeError, match="Refusing automatic stamp"):
                _run_alembic_upgrade()


def test_validate_legacy_baseline_requires_tables():
    with pytest.raises(RuntimeError, match="missing required tables"):
        _validate_legacy_baseline({"jobs"})


def test_health_ready_redacts_raw_exception_details(client: TestClient, monkeypatch):
    from app.services import health_checks

    monkeypatch.setattr(health_checks.settings, "readiness_redact_details", True)
    monkeypatch.setattr(health_checks.settings, "readiness_cache_seconds", 0)
    health_checks._cached_components = None

    async def boom_postgres():
        return health_checks._safe_error(ConnectionError("connection refused to 10.0.0.1"))

    with patch.object(health_checks, "check_postgres", boom_postgres), patch.object(
        health_checks, "check_redis", AsyncMock(return_value=ComponentHealth(status="ok"))
    ), patch.object(
        health_checks, "check_celery_broker", AsyncMock(return_value=ComponentHealth(status="ok"))
    ), patch.object(
        health_checks, "check_celery_workers", AsyncMock(return_value=ComponentHealth(status="ok"))
    ):
        response = client.get("/api/v1/health/ready")

    assert response.status_code == 503
    detail = response.json()["components"]["postgres"]["detail"]
    assert detail == "dependency unavailable"
    assert "connection refused" not in detail
    assert "10.0.0.1" not in detail


def test_metrics_requires_token_when_configured(client: TestClient, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "metrics_bearer_token", "secret-metrics")
    monkeypatch.setattr(settings, "app_env", "development")

    denied = client.get("/api/v1/metrics")
    assert denied.status_code == 401

    ok = client.get(
        "/api/v1/metrics",
        headers={"Authorization": "Bearer secret-metrics"},
    )
    assert ok.status_code == 200
    assert "secaudit_http_requests_total" in ok.text
    assert (
        "secaudit_http_request_duration_ms_count" in ok.text
        or "secaudit_http_request_duration_seconds" in ok.text
    )


def test_metrics_fail_closed_in_production_without_token(client: TestClient, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "metrics_bearer_token", None)
    monkeypatch.setattr(settings, "app_env", "production")

    response = client.get("/api/v1/metrics")
    assert response.status_code == 503


def test_redis_client_passes_socket_timeouts():
    from unittest.mock import patch as mock_patch

    from secaudit_core.celery_observability import redis_client

    with mock_patch("secaudit_core.celery_observability.sync_redis") as mock_from_url:
        redis_client("redis://localhost:6379/0", socket_connect_timeout=1.5, socket_timeout=2.5)
        kwargs = mock_from_url.call_args.kwargs
        assert kwargs["socket_connect_timeout"] == 1.5
        assert kwargs["socket_timeout"] == 2.5
