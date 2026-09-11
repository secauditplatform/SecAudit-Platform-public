import pytest
from pydantic import ValidationError

from app.schemas import JobTemplateBase, JobTemplateCreate


def test_job_template_requires_profile_or_playbook():
    with pytest.raises(ValidationError):
        JobTemplateCreate(name="preset", host_ids=[1])


def test_job_template_accepts_profile_only():
    template = JobTemplateCreate(name="weekly-linux", profile_id=1, host_ids=[])
    assert template.profile_id == 1


def test_job_template_base_validates_cron():
    template = JobTemplateBase(
        name="weekly",
        profile_id=1,
        is_scheduled=True,
        cron_expression="0 2 * * 1",
    )
    assert template.cron_expression == "0 2 * * 1"


def test_job_templates_router_requires_auth():
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        response = client.get("/api/v1/job-templates")
    assert response.status_code == 401
