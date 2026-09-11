import pytest
from pydantic import ValidationError

from app.models import ExecutionType
from app.schemas import JobCreate, RemediationJobCreate


def test_job_create_rejects_missing_targets():
    with pytest.raises(ValidationError) as exc_info:
        JobCreate(
            name="test",
            profile_id=1,
            host_ids=[],
        )
    assert "host_ids or dynamic_filter is required" in str(exc_info.value)


def test_job_create_accepts_dynamic_filter_only():
    job = JobCreate(
        name="test",
        profile_id=1,
        host_ids=[],
        dynamic_filter={"tags": ["prod"], "active_only": True},
    )
    assert job.dynamic_filter is not None
    assert job.host_ids == []


def test_remediation_job_create_rejects_missing_targets():
    with pytest.raises(ValidationError) as exc_info:
        RemediationJobCreate(
            name="remediate",
            profile_id=1,
            execution_type=ExecutionType.SSH,
            host_ids=[],
        )
    assert "host_ids or dynamic_filter is required" in str(exc_info.value)


def test_job_create_rejects_invalid_cron():
    with pytest.raises(ValidationError) as exc_info:
        JobCreate(
            name="test",
            profile_id=1,
            host_ids=[1],
            cron_expression="not a cron",
        )
    assert "Invalid cron expression" in str(exc_info.value)


def test_job_create_accepts_valid_cron():
    job = JobCreate(
        name="test",
        profile_id=1,
        host_ids=[1],
        cron_expression="0 2 * * *",
    )
    assert job.cron_expression == "0 2 * * *"
