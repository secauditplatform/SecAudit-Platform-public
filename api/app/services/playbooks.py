from datetime import UTC, datetime

from sqlalchemy import and_, exists, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.auth import AuthUser
from app.models import Host, Job, JobHost, JobRun, JobScope, JobStatus, Playbook
from app.services.dispatch import commit_and_try_dispatch, enqueue_run_dispatch
from app.services.object_rbac import (
    apply_owner_scope,
    assert_hosts_accessible,
    assert_job_run_access,
    assign_host_target_scope,
    assign_owner,
)


class PlaybookService:
    @staticmethod
    def _job_matches_platform(platform: str):
        host_os = func.lower(func.coalesce(Host.os_type, "linux"))
        if platform == "network":
            host_condition = host_os == "network"
        elif platform == "windows":
            host_condition = host_os == "windows"
        else:
            host_condition = and_(host_os != "network", host_os != "windows")

        return exists(
            select(1)
            .select_from(JobHost)
            .join(Host, JobHost.host_id == Host.id)
            .where(JobHost.job_id == Job.id, host_condition)
        )

    async def run_playbook(
        self,
        db: AsyncSession,
        user: AuthUser,
        playbook: Playbook,
        host_ids: list[int],
        connection_mode: str = "auto",
    ) -> JobRun:
        if not host_ids:
            raise ValueError("At least one host must be selected")

        await assert_hosts_accessible(db, user, host_ids)
        hosts: list[Host] = []
        for host_id in host_ids:
            host = await db.get(Host, host_id)
            if not host:
                raise LookupError(f"Host {host_id} not found")
            if not host.is_active:
                raise ValueError(f"Host '{host.name}' is inactive")
            hosts.append(host)

        stamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M")
        job = Job(
            name=f"{playbook.name} ({stamp})",
            playbook_id=playbook.id,
            is_active=False,
            is_scheduled=False,
        )
        assign_owner(job, user)
        assign_host_target_scope(job, user)
        db.add(job)
        await db.flush()

        for host in hosts:
            db.add(JobHost(job_id=job.id, host_id=host.id))

        job_run = JobRun(job_id=job.id, status=JobStatus.PENDING)
        db.add(job_run)
        await db.flush()

        outbox = await enqueue_run_dispatch(
            db,
            task_name="app.tasks.run_compliance_job",
            args=[job_run.id],
            queue="compliance",
            callback_kind="job_run",
            callback_ref_id=job_run.id,
            kwargs={"connection_mode": connection_mode},
            correlation={"run_kind": "job", "run_id": job_run.id},
        )
        await commit_and_try_dispatch(db, outbox_id=outbox.id, pending_entity=job_run)

        if job_run.status == JobStatus.FAILED:
            exc = RuntimeError(job_run.error_message or "Failed to dispatch Celery task")
            raise RuntimeError(str(exc)) from exc

        await db.refresh(job_run)
        return job_run

    async def list_playbook_runs(
        self,
        db: AsyncSession,
        user: AuthUser,
        playbook_id: int | None = None,
        scope: JobScope | None = None,
        platform: str | None = None,
        limit: int = 30,
    ) -> list[dict]:
        query = (
            select(JobRun)
            .join(Job, JobRun.job_id == Job.id)
            .where(Job.playbook_id.is_not(None))
            .options(selectinload(JobRun.job).selectinload(Job.job_hosts))
            .order_by(JobRun.created_at.desc())
            .limit(limit)
        )
        if scope is not None:
            query = query.join(Playbook, Job.playbook_id == Playbook.id).where(Playbook.scope == scope)
        if platform is not None:
            query = query.where(self._job_matches_platform(platform))
        if playbook_id is not None:
            query = query.where(Job.playbook_id == playbook_id)
        query = apply_owner_scope(query, Job.owner_sub, user)

        result = await db.execute(query)
        runs = result.scalars().all()

        playbook_ids = {run.job.playbook_id for run in runs if run.job and run.job.playbook_id}
        playbooks: dict[int, Playbook] = {}
        if playbook_ids:
            pb_result = await db.execute(select(Playbook).where(Playbook.id.in_(playbook_ids)))
            playbooks = {pb.id: pb for pb in pb_result.scalars().all()}

        payload: list[dict] = []
        for run in runs:
            job = run.job
            pb_id = job.playbook_id if job else None
            playbook = playbooks.get(pb_id) if pb_id else None
            payload.append(
                {
                    "id": run.id,
                    "job_id": run.job_id,
                    "playbook_id": pb_id,
                    "playbook_name": playbook.name if playbook else None,
                    "status": run.status,
                    "started_at": run.started_at,
                    "finished_at": run.finished_at,
                    "error_message": run.error_message,
                    "created_at": run.created_at,
                    "host_count": len(job.job_hosts) if job else 0,
                    "host_ids": [jh.host_id for jh in job.job_hosts] if job else [],
                }
            )
        return payload

    async def get_playbook_run(
        self,
        db: AsyncSession,
        user: AuthUser,
        run_id: int,
    ) -> dict:
        run = await assert_job_run_access(db, user, run_id)
        result = await db.execute(
            select(JobRun)
            .where(JobRun.id == run.id, Job.playbook_id.is_not(None))
            .join(Job, JobRun.job_id == Job.id)
            .options(selectinload(JobRun.job).selectinload(Job.job_hosts))
        )
        run = result.scalar_one_or_none()
        if not run:
            raise LookupError("Playbook run not found")
        playbook = await db.get(Playbook, run.job.playbook_id)
        return {
            "id": run.id,
            "job_id": run.job_id,
            "playbook_id": run.job.playbook_id,
            "playbook_name": playbook.name if playbook else None,
            "status": run.status,
            "started_at": run.started_at,
            "finished_at": run.finished_at,
            "error_message": run.error_message,
            "created_at": run.created_at,
            "host_count": len(run.job.job_hosts),
            "host_ids": [jh.host_id for jh in run.job.job_hosts],
        }

    async def delete_playbook(self, db: AsyncSession, playbook: Playbook) -> None:
        result = await db.execute(
            select(Job)
            .options(
                selectinload(Job.runs).selectinload(JobRun.check_results),
                selectinload(Job.job_hosts),
            )
            .where(Job.playbook_id == playbook.id)
        )
        jobs = result.scalars().all()

        for job in jobs:
            for job_run in list(job.runs):
                if job_run.status in (JobStatus.PENDING, JobStatus.RUNNING):
                    raise ValueError("Stop active playbook runs before deleting the playbook")
                for check in list(job_run.check_results):
                    await db.delete(check)
                await db.delete(job_run)
            for job_host in list(job.job_hosts):
                await db.delete(job_host)
            await db.delete(job)

        await db.flush()
        await db.delete(playbook)
