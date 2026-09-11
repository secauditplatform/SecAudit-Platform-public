from unittest.mock import MagicMock, patch

from secaudit_core.celery_dispatch import send_task


def test_send_task_forwards_deterministic_task_id():
    client = MagicMock()
    client.send_task.return_value.id = "secaudit-outbox-7"

    with patch("secaudit_core.celery_dispatch._celery_client", return_value=client):
        task_id = send_task(
            "app.tasks.run_compliance_job",
            [7],
            broker_url="memory://",
            queue="compliance",
            task_id="secaudit-outbox-7",
        )

    assert task_id == "secaudit-outbox-7"
    assert client.send_task.call_args.kwargs["task_id"] == "secaudit-outbox-7"
    assert client.send_task.call_args.kwargs["queue"] == "compliance"
