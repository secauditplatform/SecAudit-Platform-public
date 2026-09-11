"""Tests for safe profile deletion with dependency conflicts and cascade."""

from __future__ import annotations

import uuid
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.schemas import ProfileDependencies
from app.services.profiles import (
  ProfileActiveRunsError,
  ProfileDependencyError,
  ProfileService,
)
from secaudit_core.enums import CheckStatus, ExecutionType, JobStatus, OutboxStatus, WaiverStatus
from secaudit_core.models import (
  CheckResult,
  CheckScript,
  ComplianceWaiver,
  Host,
  Job,
  JobHost,
  JobRun,
  JobTemplate,
  Profile,
  RemediationJob,
  RemediationResult,
  RemediationRun,
  Rule,
  TaskOutbox,
)


async def _make_profile(db: AsyncSession, *, tech_name: str) -> Profile:
  profile = Profile(
        profile_name=tech_name,
    version="1.0.0",
    package_path=None,
    source_format="custom",
    is_active=True,
  )
  db.add(profile)
  await db.flush()
  return profile


@pytest.mark.asyncio
async def test_delete_profile_without_dependencies() -> None:
  service = ProfileService()
  engine = create_async_engine(settings.database_url)
  factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
  suffix = uuid.uuid4().hex[:8]
  async with factory() as db:
    try:
      profile = await _make_profile(db, tech_name=f"DelFree-{suffix}")
      db.add(Rule(profile_id=profile.id, tech_name="R1", title="Rule 1"))
      db.add(
        CheckScript(
          profile_id=profile.id,
          name="audit",
          execution_type=ExecutionType.SSH,
          script_file="audit.sh",
        )
      )
      await db.flush()
      profile_id = profile.id
      await service.delete_profile(db, profile_id)
      assert await service.get_profile(db, profile_id) is None
    finally:
      await db.rollback()
  await engine.dispose()


@pytest.mark.asyncio
async def test_delete_profile_conflict_with_job() -> None:
  service = ProfileService()
  engine = create_async_engine(settings.database_url)
  factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
  suffix = uuid.uuid4().hex[:8]
  async with factory() as db:
    try:
      profile = await _make_profile(db, tech_name=f"DelJob-{suffix}")
      db.add(Job(name=f"Job-{suffix}", profile_id=profile.id))
      await db.flush()
      profile_id = profile.id
      with pytest.raises(ProfileDependencyError) as exc_info:
        await service.delete_profile(db, profile_id)
      assert exc_info.value.dependencies.jobs == 1
      assert await service.get_profile(db, profile_id) is not None
    finally:
      await db.rollback()
  await engine.dispose()


@pytest.mark.asyncio
async def test_delete_profile_cascade_removes_children() -> None:
  service = ProfileService()
  engine = create_async_engine(settings.database_url)
  factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
  suffix = uuid.uuid4().hex[:8]
  async with factory() as db:
    try:
      profile = await _make_profile(db, tech_name=f"DelCascade-{suffix}")
      host = Host(name=f"h-{suffix}", hostname=f"h-{suffix}.local", port=22, is_active=True)
      db.add(host)
      await db.flush()

      job = Job(name=f"Job-{suffix}", profile_id=profile.id)
      db.add(job)
      await db.flush()
      db.add(JobHost(job_id=job.id, host_id=host.id))
      run = JobRun(job_id=job.id, status=JobStatus.COMPLETED)
      db.add(run)
      await db.flush()
      db.add(
        CheckResult(
          job_run_id=run.id,
          host_id=host.id,
          rule_tech_name="R1",
          status=CheckStatus.PASS,
        )
      )
      db.add(
        ComplianceWaiver(
          profile_id=profile.id,
          rule_tech_name="R1",
          reason="temp",
          status=WaiverStatus.APPROVED,
          requested_by="tester",
          is_active=True,
        )
      )
      template = JobTemplate(name=f"tmpl-{suffix}", profile_id=profile.id, is_active=True)
      db.add(template)

      rem_job = RemediationJob(
        name=f"Rem-{suffix}",
        profile_id=profile.id,
        execution_type=ExecutionType.SSH,
      )
      db.add(rem_job)
      await db.flush()
      rem_run = RemediationRun(remediation_job_id=rem_job.id, status=JobStatus.COMPLETED)
      db.add(rem_run)
      await db.flush()
      db.add(
        RemediationResult(
          remediation_run_id=rem_run.id,
          host_id=host.id,
          script_name="fix.sh",
          status=CheckStatus.PASS,
        )
      )
      await db.flush()

      profile_id = profile.id
      job_id = job.id
      rem_job_id = rem_job.id
      template_id = template.id
      run_id = run.id

      await service.delete_profile(db, profile_id, cascade=True)

      assert await service.get_profile(db, profile_id) is None
      assert (await db.execute(select(Job).where(Job.id == job_id))).scalar_one_or_none() is None
      assert (
        await db.execute(select(RemediationJob).where(RemediationJob.id == rem_job_id))
      ).scalar_one_or_none() is None
      assert (
        await db.execute(select(JobRun).where(JobRun.id == run_id))
      ).scalar_one_or_none() is None
      assert (
        await db.execute(select(CheckResult).where(CheckResult.job_run_id == run_id))
      ).scalars().first() is None
      assert (
        await db.execute(
          select(ComplianceWaiver).where(ComplianceWaiver.profile_id == profile_id)
        )
      ).scalars().first() is None
      refreshed = (
        await db.execute(select(JobTemplate).where(JobTemplate.id == template_id))
      ).scalar_one()
      assert refreshed.profile_id is None
    finally:
      await db.rollback()
  await engine.dispose()


@pytest.mark.asyncio
async def test_delete_profile_cascade_cancels_dispatchable_outbox() -> None:
  service = ProfileService()
  engine = create_async_engine(settings.database_url)
  factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
  suffix = uuid.uuid4().hex[:8]
  async with factory() as db:
    try:
      profile = await _make_profile(db, tech_name=f"DelOutbox-{suffix}")
      job = Job(name=f"Job-{suffix}", profile_id=profile.id)
      db.add(job)
      await db.flush()
      run = JobRun(job_id=job.id, status=JobStatus.COMPLETED)
      db.add(run)
      rem_job = RemediationJob(
        name=f"Rem-{suffix}",
        profile_id=profile.id,
        execution_type=ExecutionType.SSH,
      )
      db.add(rem_job)
      await db.flush()
      rem_run = RemediationRun(remediation_job_id=rem_job.id, status=JobStatus.COMPLETED)
      db.add(rem_run)
      await db.flush()

      job_outbox = TaskOutbox(
        task_name="app.tasks.run_compliance_job",
        args_json=f"[{run.id}]",
        queue="compliance",
        status=OutboxStatus.PENDING,
        callback_kind="job_run",
        callback_ref_id=run.id,
        celery_task_id=f"secaudit-outbox-job-{suffix}",
      )
      rem_outbox = TaskOutbox(
        task_name="app.tasks.run_remediation_job",
        args_json=f"[{rem_run.id}]",
        queue="remediation",
        status=OutboxStatus.DISPATCHING,
        callback_kind="remediation_run",
        callback_ref_id=rem_run.id,
        celery_task_id=f"secaudit-outbox-rem-{suffix}",
      )
      unrelated = TaskOutbox(
        task_name="app.tasks.run_compliance_job",
        args_json="[999999]",
        queue="compliance",
        status=OutboxStatus.PENDING,
        callback_kind="job_run",
        callback_ref_id=999999,
        celery_task_id=f"secaudit-outbox-other-{suffix}",
      )
      db.add_all([job_outbox, rem_outbox, unrelated])
      await db.flush()

      profile_id = profile.id
      job_outbox_id = job_outbox.id
      rem_outbox_id = rem_outbox.id
      unrelated_id = unrelated.id
      run_id = run.id
      rem_run_id = rem_run.id

      await service.delete_profile(db, profile_id, cascade=True)

      job_row = (
        await db.execute(select(TaskOutbox).where(TaskOutbox.id == job_outbox_id))
      ).scalar_one()
      rem_row = (
        await db.execute(select(TaskOutbox).where(TaskOutbox.id == rem_outbox_id))
      ).scalar_one()
      other_row = (
        await db.execute(select(TaskOutbox).where(TaskOutbox.id == unrelated_id))
      ).scalar_one()

      assert job_row.status == OutboxStatus.CANCELLED
      assert rem_row.status == OutboxStatus.CANCELLED
      assert other_row.status == OutboxStatus.PENDING

      dispatchable = (
        await db.execute(
          select(TaskOutbox).where(
            TaskOutbox.callback_kind.in_(("job_run", "remediation_run")),
            TaskOutbox.callback_ref_id.in_((run_id, rem_run_id)),
            TaskOutbox.status.in_((OutboxStatus.PENDING, OutboxStatus.DISPATCHING)),
          )
        )
      ).scalars().all()
      assert dispatchable == []
    finally:
      await db.rollback()
  await engine.dispose()


@pytest.mark.asyncio
async def test_delete_profile_cascade_blocked_by_active_run() -> None:
  service = ProfileService()
  engine = create_async_engine(settings.database_url)
  factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
  suffix = uuid.uuid4().hex[:8]
  async with factory() as db:
    try:
      profile = await _make_profile(db, tech_name=f"DelActive-{suffix}")
      job = Job(name=f"Job-{suffix}", profile_id=profile.id)
      db.add(job)
      await db.flush()
      db.add(JobRun(job_id=job.id, status=JobStatus.RUNNING))
      await db.flush()
      profile_id = profile.id

      with pytest.raises(ProfileActiveRunsError) as exc_info:
        await service.delete_profile(db, profile_id, cascade=True)
      assert exc_info.value.dependencies.active_runs == 1
      assert await service.get_profile(db, profile_id) is not None
    finally:
      await db.rollback()
  await engine.dispose()


def test_delete_profile_route_conflict_and_cascade(
  client: TestClient, operator_headers: dict[str, str]
) -> None:
  deps = ProfileDependencies(
    jobs=2,
    remediation_jobs=1,
    waivers=0,
    job_runs=3,
    check_results=5,
    remediation_runs=1,
    active_runs=0,
  )
  conflict = ProfileDependencyError(deps)

  with patch(
    "app.api.v1.routers.profiles.profile_service.get_profile",
    new=AsyncMock(return_value=SimpleNamespace(id=7, profile_name="Demo")),
  ), patch(
    "app.api.v1.routers.profiles.profile_service.delete_profile",
    new=AsyncMock(side_effect=conflict),
  ), patch(
    "app.api.v1.routers.profiles.log_audit_event",
    new=AsyncMock(),
  ):
    response = client.delete("/api/v1/profiles/7", headers=operator_headers)

  assert response.status_code == 409
  detail = response.json()["detail"]
  assert detail["code"] == "profile_has_dependencies"
  assert detail["dependencies"]["jobs"] == 2

  with patch(
    "app.api.v1.routers.profiles.profile_service.get_profile",
    new=AsyncMock(return_value=SimpleNamespace(id=7, profile_name="Demo")),
  ), patch(
    "app.api.v1.routers.profiles.profile_service.delete_profile",
    new=AsyncMock(return_value=None),
  ) as delete_mock, patch(
    "app.api.v1.routers.profiles.log_audit_event",
    new=AsyncMock(),
  ):
    response = client.delete("/api/v1/profiles/7?cascade=true", headers=operator_headers)

  assert response.status_code == 204
  delete_mock.assert_awaited_once()
  assert delete_mock.await_args.kwargs.get("cascade") is True


def test_delete_profile_route_rbac_auditor_forbidden(client: TestClient) -> None:
  from app.core.auth import create_local_token
  from app.models import UserRole

  auditor_headers = {
    "Authorization": f"Bearer {create_local_token('auditor', [UserRole.AUDITOR.value])}"
  }
  response = client.delete("/api/v1/profiles/1", headers=auditor_headers)
  assert response.status_code == 403


def test_get_profile_dependencies_route(
  client: TestClient, operator_headers: dict[str, str]
) -> None:
  payload = ProfileDependencies(jobs=1, job_runs=2, check_results=4)
  with patch(
    "app.api.v1.routers.profiles.profile_service.get_profile_dependencies",
    new=AsyncMock(return_value=payload),
  ):
    response = client.get("/api/v1/profiles/9/dependencies", headers=operator_headers)

  assert response.status_code == 200
  assert response.json()["jobs"] == 1
  assert response.json()["check_results"] == 4


def test_bulk_delete_profiles_reports_dependencies(
  client: TestClient, operator_headers: dict[str, str]
) -> None:
  with patch(
    "app.api.v1.routers.profiles.profile_service.bulk_delete",
    new=AsyncMock(
      return_value={
        "succeeded": [1],
        "failed": [
          {
            "profile_id": 2,
            "message": "Profile is referenced by dependent resources",
            "code": "profile_has_dependencies",
            "dependencies": {
              "jobs": 1,
              "remediation_jobs": 0,
              "waivers": 0,
              "job_runs": 0,
              "check_results": 0,
              "remediation_runs": 0,
              "active_runs": 0,
            },
          }
        ],
      }
    ),
  ), patch(
    "app.api.v1.routers.profiles.log_audit_event",
    new=AsyncMock(),
  ):
    response = client.post(
      "/api/v1/profiles/bulk/delete",
      headers=operator_headers,
      json={"profile_ids": [1, 2], "cascade": False},
    )

  assert response.status_code == 200
  body = response.json()
  assert body["succeeded"] == [1]
  assert body["failed"][0]["code"] == "profile_has_dependencies"
  assert body["failed"][0]["dependencies"]["jobs"] == 1
