from unittest.mock import MagicMock, patch

from app.logging_pub import publish_audit_flow_log, publish_job_log, publish_remediation_log


@patch("app.logging_pub._redis_client")
def test_publish_job_log_writes_to_pubsub_and_list(mock_redis_client):
    client = MagicMock()
    mock_redis_client.return_value = client

    publish_job_log(146, "Job run #146 started")

    client.publish.assert_called_once()
    channel, payload = client.publish.call_args.args
    assert channel == "job_run:146"
    assert "Job run #146 started" in payload
    client.lpush.assert_called_once_with("job_run_logs:146", payload)
    client.expire.assert_called_once()


@patch("app.logging_pub._redis_client")
def test_publish_remediation_log_writes_to_pubsub_and_list(mock_redis_client):
    client = MagicMock()
    mock_redis_client.return_value = client

    publish_remediation_log(12, "Remediation started")

    client.publish.assert_called_once()
    channel, payload = client.publish.call_args.args
    assert channel == "remediation_run:12"
    assert "Remediation started" in payload
    client.lpush.assert_called_once_with("remediation_run_logs:12", payload)


@patch("app.logging_pub._redis_client")
def test_publish_audit_flow_log_writes_to_pubsub_and_list(mock_redis_client):
    client = MagicMock()
    mock_redis_client.return_value = client

    publish_audit_flow_log(7, "Task #7 started")

    channel, payload = client.publish.call_args.args
    assert channel == "audit_flow_run:7"
    assert "Task #7 started" in payload
    client.lpush.assert_called_once_with("audit_flow_run_logs:7", payload)


@patch("app.logging_pub.logger")
@patch("app.logging_pub._redis_client", side_effect=RuntimeError("redis down"))
def test_publish_job_log_logs_redis_failures(mock_redis_client, mock_logger):
    publish_job_log(146, "should fail quietly to caller")

    mock_logger.exception.assert_called_once()
