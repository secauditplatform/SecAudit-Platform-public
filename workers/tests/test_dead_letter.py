"""SecAuditTask dead-letter hook."""

from unittest.mock import MagicMock, PropertyMock, patch

from secaudit_core.celery_task import SecAuditTask


class _DummyTask(SecAuditTask):
    name = "app.tasks.test.dummy"


@patch("celery.app.task.Task.on_failure")
@patch("secaudit_core.celery_task.persist_dead_letter_from_task")
@patch("secaudit_core.celery_task.SecAuditSettings")
def test_sec_audit_task_on_failure_persists_dead_letter(
    mock_settings_cls, mock_persist, mock_super_on_failure
):
    settings = mock_settings_cls.return_value
    settings.database_url_sync = "postgresql://test/db"
    settings.redis_url = "redis://localhost:6379/0"

    task = _DummyTask()
    mock_request = MagicMock(
        delivery_info={"routing_key": "compliance"},
        retries=3,
    )

    exc = RuntimeError("permanent failure")
    with patch.object(type(task), "request", new_callable=PropertyMock, return_value=mock_request):
        task.on_failure(exc, "task-id-1", [1], {"foo": "bar"}, None)

    mock_persist.assert_called_once()
    kwargs = mock_persist.call_args.kwargs
    assert kwargs["celery_task_id"] == "task-id-1"
    assert kwargs["task_name"] == "app.tasks.test.dummy"
    assert kwargs["retry_count"] == 3
    assert kwargs["exc"] is exc
    mock_super_on_failure.assert_called_once()
