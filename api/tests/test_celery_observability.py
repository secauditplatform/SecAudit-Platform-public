"""Tests for Celery/worker observability helpers."""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from secaudit_core.celery_observability import (
    WORKER_HEARTBEAT_KEY,
    fetch_outbox_stats,
    queue_depths,
    record_outbox_dispatch_failure,
    record_outbox_dispatch_lag,
    record_task_metric,
    render_celery_prometheus_metrics,
    touch_worker_heartbeat,
    worker_heartbeat_age_seconds,
)


def test_touch_worker_heartbeat_and_age_roundtrip():
    with patch("secaudit_core.celery_observability.sync_redis") as mock_from_url:
        client = mock_from_url.return_value
        client.get.return_value = datetime.now(UTC).isoformat()

        touch_worker_heartbeat("redis://localhost:6379/0")
        age = worker_heartbeat_age_seconds("redis://localhost:6379/0")

        client.set.assert_called_once()
        assert client.set.call_args.args[0] == WORKER_HEARTBEAT_KEY
        assert age is not None
        assert age >= 0


def test_record_task_metric_and_render_prometheus():
    with patch("secaudit_core.celery_observability.sync_redis") as mock_from_url:
        client = mock_from_url.return_value
        client.hgetall.side_effect = [
            {"app.tasks.run_compliance_job|SUCCESS": "2"},
            {"app.tasks.run_compliance_job": "1500.5"},
            {},
        ]
        client.get.side_effect = [
            None,
            "0",
            "0",
            "0",
        ]
        client.llen.return_value = 0

        record_task_metric(
            "redis://localhost:6379/0",
            task_name="app.tasks.run_compliance_job",
            status="SUCCESS",
            duration_ms=750.25,
        )
        metrics = render_celery_prometheus_metrics(
            "redis://localhost:6379/0",
            outbox_stats={
                "pending": 2.0,
                "dispatching": 1.0,
                "oldest_pending_age_seconds": 12.5,
                "oldest_dispatching_age_seconds": 3.0,
            },
        )

    assert "secaudit_celery_tasks_total" in metrics
    assert "secaudit_celery_task_duration_ms_sum" in metrics
    assert "secaudit_celery_queue_depth" in metrics
    assert "secaudit_outbox_pending 2" in metrics
    assert "secaudit_outbox_dispatching 1" in metrics
    assert "secaudit_outbox_oldest_pending_age_seconds 12.5" in metrics
    assert "secaudit_outbox_dispatch_lag_seconds_sum" in metrics


def test_record_outbox_dispatch_lag_and_failure():
    with patch("secaudit_core.celery_observability.sync_redis") as mock_from_url:
        client = mock_from_url.return_value
        record_outbox_dispatch_lag("redis://localhost:6379/0", 1.25)
        record_outbox_dispatch_failure("redis://localhost:6379/0")

    client.incrbyfloat.assert_called_once()
    client.incr.assert_called()


def test_worker_heartbeat_age_returns_none_when_missing():
    with patch("secaudit_core.celery_observability.sync_redis") as mock_from_url:
        client = mock_from_url.return_value
        client.get.return_value = None
        assert worker_heartbeat_age_seconds("redis://localhost:6379/0") is None


def test_worker_heartbeat_age_detects_stale_timestamp():
    stale = (datetime.now(UTC) - timedelta(seconds=300)).isoformat()
    with patch("secaudit_core.celery_observability.sync_redis") as mock_from_url:
        client = mock_from_url.return_value
        client.get.return_value = stale
        age = worker_heartbeat_age_seconds("redis://localhost:6379/0")
    assert age is not None
    assert age >= 300


def test_fetch_outbox_stats_sqlite(tmp_path):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from secaudit_core.enums import OutboxStatus
    from secaudit_core.models import Base, TaskOutbox

    db_path = tmp_path / "outbox_metrics.db"
    db_url = f"sqlite+pysqlite:///{db_path.as_posix()}"
    engine = create_engine(db_url)
    Base.metadata.create_all(engine)
    now = datetime.now(UTC)
    with Session(engine) as session:
        session.add_all(
            [
                TaskOutbox(
                    task_name="task.a",
                    args_json="[]",
                    queue="compliance",
                    status=OutboxStatus.PENDING,
                    created_at=now - timedelta(seconds=30),
                ),
                TaskOutbox(
                    task_name="task.b",
                    args_json="[]",
                    queue="compliance",
                    status=OutboxStatus.DISPATCHING,
                    dispatch_started_at=now - timedelta(seconds=5),
                ),
            ]
        )
        session.commit()

    stats = fetch_outbox_stats(db_url)
    assert stats["pending"] == 1.0
    assert stats["dispatching"] == 1.0
    assert stats["oldest_pending_age_seconds"] is not None
    assert stats["oldest_pending_age_seconds"] >= 30
    assert stats["oldest_dispatching_age_seconds"] is not None
