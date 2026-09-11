from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.tasks import compliance, remediation
from secaudit_core.base import Base
from secaudit_core.enums import ExecutionType, JobStatus, OutboxStatus
from secaudit_core.models import (
    Job,
    JobRun,
    RemediationJob,
    RemediationRun,
    TaskOutbox,
)


def _session_factory(tmp_path):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'dispatch.db'}")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def test_scheduled_compliance_creates_pending_run_and_outbox(tmp_path, monkeypatch):
    sessions = _session_factory(tmp_path)
    monkeypatch.setattr(compliance, "SessionLocal", sessions)
    with sessions() as db:
        job = Job(
            name="scheduled",
            cron_expression="* * * * *",
            is_scheduled=True,
            is_active=True,
        )
        db.add(job)
        db.commit()

    result = compliance._run_scheduled_jobs_locked()

    assert result["count"] == 1
    with sessions() as db:
        run = db.execute(select(JobRun)).scalar_one()
        outbox = db.execute(select(TaskOutbox)).scalar_one()
        assert run.status == JobStatus.PENDING
        assert run.started_at is None
        assert outbox.status == OutboxStatus.PENDING
        assert outbox.callback_kind == "job_run"
        assert outbox.callback_ref_id == run.id


def test_scheduled_remediation_creates_pending_run_and_outbox(tmp_path, monkeypatch):
    sessions = _session_factory(tmp_path)
    monkeypatch.setattr(remediation, "SessionLocal", sessions)
    with sessions() as db:
        job = RemediationJob(
            name="scheduled remediation",
            profile_id=1,
            execution_type=ExecutionType.SSH,
            cron_expression="* * * * *",
            is_scheduled=True,
            is_active=True,
        )
        db.add(job)
        db.commit()

    result = remediation._run_scheduled_remediation_jobs_locked()

    assert result["count"] == 1
    with sessions() as db:
        run = db.execute(select(RemediationRun)).scalar_one()
        outbox = db.execute(select(TaskOutbox)).scalar_one()
        assert run.status == JobStatus.PENDING
        assert run.started_at is None
        assert outbox.status == OutboxStatus.PENDING
        assert outbox.callback_kind == "remediation_run"
        assert outbox.callback_ref_id == run.id


def test_remediation_redelivery_does_not_reexecute_running_run(tmp_path, monkeypatch):
    sessions = _session_factory(tmp_path)
    monkeypatch.setattr(remediation, "SessionLocal", sessions)
    with sessions() as db:
        run = RemediationRun(
            remediation_job_id=1,
            status=JobStatus.RUNNING,
        )
        db.add(run)
        db.commit()
        run_id = run.id

    result = remediation.run_remediation_job.run(run_id)

    assert result == {
        "remediation_run_id": run_id,
        "status": JobStatus.RUNNING.value,
        "claimed": False,
    }


def test_compliance_cancelled_delivery_never_revives_run(tmp_path, monkeypatch):
    sessions = _session_factory(tmp_path)
    monkeypatch.setattr(compliance, "SessionLocal", sessions)
    with sessions() as db:
        run = JobRun(job_id=1, status=JobStatus.CANCELLED)
        db.add(run)
        db.commit()
        run_id = run.id

    result = compliance.run_compliance_job.run(run_id)

    assert result["claimed"] is False
    with sessions() as db:
        assert db.get(JobRun, run_id).status == JobStatus.CANCELLED
