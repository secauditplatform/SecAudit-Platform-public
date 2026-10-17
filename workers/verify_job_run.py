"""Verify job run completes after commit-before-dispatch fix."""
import time

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.celery_app import settings
from secaudit_core.models import JobRun, JobStatus
from secaudit_core.task_outbox import enqueue_outbox_row, try_dispatch_outbox_by_id

engine = create_engine(settings.database_url_sync)
Session = sessionmaker(bind=engine)

with Session() as db:
    job_run = JobRun(job_id=3, status=JobStatus.PENDING)
    db.add(job_run)
    db.flush()
    run_id = job_run.id
    outbox = enqueue_outbox_row(
        db,
        task_name="app.tasks.run_compliance_job",
        args=[run_id],
        queue="compliance",
        callback_kind="job_run",
        callback_ref_id=run_id,
    )
    outbox_id = outbox.id
    db.commit()
    print("created run", run_id)

with Session() as db:
    dispatched = try_dispatch_outbox_by_id(
        db,
        outbox_id,
        broker_url=settings.celery_broker_url,
    )
    print("dispatched", dispatched)

for _ in range(15):
    time.sleep(1)
    with Session() as db:
        run = db.get(JobRun, run_id)
        print("status", run.status.value if run else "missing", run.finished_at if run else "")
        if run and run.finished_at:
            break
