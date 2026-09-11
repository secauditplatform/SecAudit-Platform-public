"""Regression: async API session must persist task_outbox rows (outboxstatus enum case)."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings
from app.models import JobRun, JobStatus
from app.services.task_outbox import enqueue_task_outbox
from secaudit_core.enums import OutboxStatus


@pytest.mark.asyncio
async def test_async_enqueue_task_outbox_accepts_pending_status():
    engine = create_async_engine(settings.database_url)
    session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with session_factory() as db:
        row = await enqueue_task_outbox(
            db,
            task_name="app.tasks.run_compliance_job",
            args=[1],
            queue="compliance",
            callback_kind="job_run",
            callback_ref_id=1,
            correlation={"run_kind": "job", "run_id": 1},
        )
        assert row.status == OutboxStatus.PENDING
        await db.rollback()
    await engine.dispose()
