"""Redis integration via Testcontainers for observability metrics."""

import os
from pathlib import Path

import pytest
from testcontainers.redis import RedisContainer

from secaudit_core.celery_observability import (
    record_task_metric,
    render_celery_prometheus_metrics,
    touch_worker_heartbeat,
    worker_heartbeat_age_seconds,
)


def _docker_socket_available() -> bool:
    return any(Path(path).exists() for path in ("/var/run/docker.sock", "/run/docker.sock"))


@pytest.mark.integration
def test_redis_observability_with_testcontainers():
    if not _docker_socket_available():
        pytest.skip("Docker socket not available (run on host CI, not inside api container)")
    with RedisContainer("redis:7-alpine") as redis_container:
        redis_url = f"redis://{redis_container.get_container_host_ip()}:{redis_container.get_exposed_port(6379)}/0"
        touch_worker_heartbeat(redis_url)
        age = worker_heartbeat_age_seconds(redis_url)
        record_task_metric(
            redis_url,
            task_name="app.tasks.run_compliance_job",
            status="SUCCESS",
            duration_ms=42.0,
        )
        metrics = render_celery_prometheus_metrics(redis_url)

    assert age is not None
    assert "secaudit_celery_tasks_total" in metrics
    assert "secaudit_celery_queue_depth" in metrics
