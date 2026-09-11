import pytest
from pydantic import ValidationError

from app.schemas import NotificationChannelCreate, ScheduledReportCreate
from secaudit_core.enums import (
    NotificationChannelType,
    ScheduledReportDelivery,
    ScheduledReportFormat,
)
from secaudit_core.sensitive_data import REDACTED, redact_sensitive


def test_notification_config_rejects_nested_secret_keys():
    with pytest.raises(ValidationError):
        NotificationChannelCreate(
            name="unsafe",
            channel_type=NotificationChannelType.WEBHOOK,
            config_json={"headers": {"Authorization": "Bearer plaintext"}},
        )


def test_schedule_config_rejects_credential_url():
    with pytest.raises(ValidationError):
        ScheduledReportCreate(
            name="unsafe",
            job_id=1,
            cron_expression="0 1 * * *",
            report_format=ScheduledReportFormat.PDF,
            delivery_type=ScheduledReportDelivery.S3,
            config_json={"endpoint_url": "https://user:password@s3.example.test"},
        )


def test_legacy_config_is_recursively_redacted_for_responses_and_audit():
    legacy = {
        "smtp_password": "plaintext",
        "nested": {"api-token": "plaintext"},
        "endpoint_url": "https://user:password@example.test/path",
    }
    redacted = redact_sensitive(legacy)
    assert redacted["smtp_password"] == REDACTED
    assert redacted["nested"]["api-token"] == REDACTED
    assert "password" not in redacted["endpoint_url"]
    assert REDACTED in redacted["endpoint_url"]
