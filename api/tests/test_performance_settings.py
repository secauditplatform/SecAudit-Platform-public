from unittest.mock import patch

import pytest

from secaudit_core.celery_dispatch import send_task
from secaudit_core.settings import SecAuditSettings


def test_send_task_passes_queue_to_celery():
    mock_result = type("AsyncResult", (), {"id": "task-xyz"})()
    mock_client = type("Client", (), {})()
    mock_client.send_task = lambda *args, **kwargs: mock_result

    with patch("secaudit_core.celery_dispatch._celery_client", return_value=mock_client):
        captured: dict = {}

        def capture_send_task(task_name, args, kwargs=None, **options):
            captured["task_name"] = task_name
            captured["args"] = args
            captured["options"] = options
            return mock_result

        mock_client.send_task = capture_send_task
        task_id = send_task(
            "app.tasks.inventory.run_inventory_scan_task",
            [42],
            broker_url="redis://localhost:6379/0",
            queue="inventory",
        )

    assert task_id == "task-xyz"
    assert captured["task_name"] == "app.tasks.inventory.run_inventory_scan_task"
    assert captured["args"] == [42]
    assert captured["options"] == {"queue": "inventory"}


def test_job_host_concurrency_default():
    settings = SecAuditSettings()
    assert settings.job_host_concurrency == 4


def test_job_host_concurrency_from_env(monkeypatch):
    monkeypatch.setenv("JOB_HOST_CONCURRENCY", "5")
    settings = SecAuditSettings()
    assert settings.job_host_concurrency == 5


def test_log_ttl_and_raw_output_defaults():
    settings = SecAuditSettings()
    assert settings.job_log_ttl_seconds == 86400
    assert settings.raw_output_max_chars == 16000
