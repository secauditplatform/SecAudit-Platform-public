from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.services.dispatch import (
    cancel_active_run,
    commit_and_try_dispatch,
    correlation_from_request,
    enqueue_run_dispatch,
)

from secaudit_core.celery_dispatch import revoke_task
from secaudit_core.notifications import enqueue_run_notification, events_for_terminal_status

from app.core.auth import AuthUser, require_roles
from app.core.roles import require_reports
from app.core.config import settings
from app.core.database import get_db
from app.models import Host, Job, JobHost, JobRun, JobScope, JobStatus, UserRole
from app.pagination import paginate_scalars, pagination_params
from app.schemas import CheckResultRead, JobCreate, JobRead, JobRunDetail, JobRunRead, JobUpdate, PaginatedResponse
from app.services.audit_log import log_audit_event
from app.services.job_webhooks import apply_webhook_fields, webhook_read_fields
from app.services.network_jobs import validate_job_scope
from app.services.object_rbac import (
    apply_owner_scope,
    assert_can_access,
    assert_hosts_accessible,
    assign_host_target_scope,
    assign_owner,
)

router = APIRouter()


def _revoke_celery_task(task_id: str) -> None:
    revoke_task(task_id, broker_url=settings.celery_broker_url)


def _job_to_read(job: Job) -> JobRead:
    return JobRead(
        id=job.id,
        name=job.name,
        profile_id=job.profile_id,
        playbook_id=job.playbook_id,
        execution_type=job.execution_type,
        dynamic_filter=job.dynamic_filter,
        scope=job.scope,
        network_check_mode=job.network_check_mode,
        cron_expression=job.cron_expression,
        is_scheduled=job.is_scheduled,
        is_active=job.is_active,
        created_at=job.created_at,
        owner_sub=job.owner_sub,
        host_ids=[jh.host_id for jh in job.job_hosts],
        **webhook_read_fields(job),
    )


@router.get("", response_model=list[JobRead])
async def list_jobs(
    scope: JobScope | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_reports),
) -> list[JobRead]:
    stmt = select(Job).options(selectinload(Job.job_hosts)).order_by(Job.created_at.desc())
    if scope is not None:
        stmt = stmt.where(Job.scope == scope)
    stmt = apply_owner_scope(stmt, Job.owner_sub, user)
    result = await db.execute(stmt)
    return [_job_to_read(j) for j in result.scalars().all()]


@router.post("", response_model=JobRead, status_code=201)
async def create_job(
    data: JobCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> JobRead:
    if not data.profile_id and not data.playbook_id:
        raise HTTPException(status_code=400, detail="profile_id or playbook_id is required")
    network_check_mode = await validate_job_scope(
        db,
        scope=data.scope,
        profile_id=data.profile_id,
        host_ids=data.host_ids,
        network_check_mode=data.network_check_mode,
    )
    job = Job(
        **data.model_dump(
            exclude={"host_ids", "webhook_url", "webhook_enabled", "webhook_events", "network_check_mode"}
        ),
        network_check_mode=network_check_mode,
    )
    apply_webhook_fields(
        job,
        settings=settings,
        webhook_enabled=data.webhook_enabled,
        webhook_events=data.webhook_events,
        webhook_url=data.webhook_url,
    )
    assign_owner(job, user)
    assign_host_target_scope(job, user)
    db.add(job)
    await db.flush()

    await assert_hosts_accessible(db, user, data.host_ids)
    for host_id in data.host_ids:
        db.add(JobHost(job_id=job.id, host_id=host_id))

    await db.flush()
    result = await db.execute(select(Job).options(selectinload(Job.job_hosts)).where(Job.id == job.id))
    await log_audit_event(
        db,
        request,
        user,
        action="job.create",
        resource_type="job",
        resource_id=job.id,
        resource_name=job.name,
    )
    return _job_to_read(result.scalar_one())


@router.patch("/{job_id}", response_model=JobRead)
async def update_job(
    job_id: int,
    data: JobUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> JobRead:
    result = await db.execute(
        select(Job).options(selectinload(Job.job_hosts)).where(Job.id == job_id)
    )
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    assert_can_access(user, job.owner_sub, detail="Job not found")

    updates = data.model_dump(exclude_unset=True)
    host_ids = updates.pop("host_ids", None)
    webhook_url = updates.pop("webhook_url", None)
    clear_webhook_url = updates.pop("clear_webhook_url", None)
    webhook_enabled = updates.pop("webhook_enabled", None)
    webhook_events = updates.pop("webhook_events", None)
    network_check_mode = updates.pop("network_check_mode", None)

    merged_scope = updates.get("scope", job.scope)
    merged_profile_id = updates.get("profile_id", job.profile_id)
    merged_host_ids = host_ids if host_ids is not None else [jh.host_id for jh in job.job_hosts]
    resolved_network_mode = await validate_job_scope(
        db,
        scope=merged_scope,
        profile_id=merged_profile_id,
        host_ids=merged_host_ids,
        network_check_mode=network_check_mode if network_check_mode is not None else job.network_check_mode,
    )
    job.network_check_mode = resolved_network_mode

    for field, value in updates.items():
        setattr(job, field, value)

    apply_webhook_fields(
        job,
        settings=settings,
        webhook_enabled=webhook_enabled,
        webhook_events=webhook_events,
        webhook_url=webhook_url,
        clear_webhook_url=clear_webhook_url,
    )

    if not job.profile_id and not job.playbook_id:
        raise HTTPException(status_code=400, detail="profile_id or playbook_id is required")
    if host_ids is not None:
        await assert_hosts_accessible(db, user, host_ids)
        for jh in list(job.job_hosts):
            await db.delete(jh)
        for host_id in host_ids:
            db.add(JobHost(job_id=job.id, host_id=host_id))

    await db.flush()
    result = await db.execute(select(Job).options(selectinload(Job.job_hosts)).where(Job.id == job.id))
    await log_audit_event(
        db,
        request,
        user,
        action="job.update",
        resource_type="job",
        resource_id=job.id,
        resource_name=job.name,
    )
    return _job_to_read(result.scalar_one())


@router.get("/runs", response_model=PaginatedResponse[JobRunRead])
async def list_job_runs(
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_reports),
    page: tuple[int, int] = Depends(pagination_params),
) -> PaginatedResponse[JobRunRead]:
    offset, limit = page
    stmt = select(JobRun).join(Job, Job.id == JobRun.job_id)
    stmt = apply_owner_scope(stmt, Job.owner_sub, user)
    stmt = stmt.order_by(JobRun.created_at.desc())
    runs, total = await paginate_scalars(db, stmt, offset=offset, limit=limit)
    return PaginatedResponse(
        items=[JobRunRead.model_validate(r) for r in runs],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.post("/{job_id}/run", response_model=JobRunRead, status_code=201)
async def run_job(
    job_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> JobRunRead:
    result = await db.execute(select(Job).where(Job.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    assert_can_access(user, job.owner_sub, detail="Job not found")

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
        correlation=correlation_from_request(request, run_kind="job", run_id=job_run.id),
    )
    await commit_and_try_dispatch(db, outbox_id=outbox.id, pending_entity=job_run)

    if job_run.status == JobStatus.FAILED:
        exc = RuntimeError(job_run.error_message or "Failed to dispatch Celery task")
        await log_audit_event(
            db,
            request,
            user,
            action="job.run",
            resource_type="job",
            resource_id=job.id,
            resource_name=job.name,
            outcome="failed",
            metadata={"run_id": job_run.id, "error": str(exc)},
        )
        await db.commit()
        enqueue_run_notification(
            broker_url=settings.celery_broker_url,
            settings=settings,
            trigger_events=events_for_terminal_status(JobStatus.FAILED, source="dispatch"),
            run_kind="job",
            run_id=job_run.id,
            job_id=job.id,
            job_name=job.name,
            status=JobStatus.FAILED.value,
            error_message=str(exc),
            owner_sub=job.owner_sub,
        )
        await db.refresh(job_run)
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    await db.flush()
    await db.refresh(job_run)
    await log_audit_event(
        db,
        request,
        user,
        action="job.run",
        resource_type="job",
        resource_id=job.id,
        resource_name=job.name,
        metadata={"run_id": job_run.id},
    )
    return JobRunRead.model_validate(job_run)


@router.get("/runs/{run_id}", response_model=JobRunDetail)
async def get_job_run(
    run_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_reports),
) -> JobRunDetail:
    from secaudit_core.waivers import load_active_waivers, waived_fail_ids

    result = await db.execute(
        select(JobRun)
        .options(selectinload(JobRun.check_results), selectinload(JobRun.job))
        .where(JobRun.id == run_id)
    )
    job_run = result.scalar_one_or_none()
    if not job_run:
        raise HTTPException(status_code=404, detail="Job run not found")
    assert_can_access(user, job_run.job.owner_sub if job_run.job else None, detail="Job run not found")

    waived_map = {}
    if job_run.job and job_run.job.profile_id is not None:
        waivers = await load_active_waivers(
            db, profile_id=job_run.job.profile_id, job_id=job_run.job_id
        )
        waived_map = waived_fail_ids(
            job_run.check_results,
            waivers,
            profile_id=job_run.job.profile_id,
            job_id=job_run.job_id,
        )

    host_ids = {check.host_id for check in job_run.check_results}
    hosts_by_id: dict[int, Host] = {}
    if host_ids:
        hosts_result = await db.execute(select(Host).where(Host.id.in_(host_ids)))
        hosts_by_id = {host.id: host for host in hosts_result.scalars().all()}

    check_results = []
    for check in job_run.check_results:
        host = hosts_by_id.get(check.host_id)
        host_name = None
        if host is not None:
            host_name = (host.name or "").strip() or (host.hostname or "").strip() or None
        payload = CheckResultRead.model_validate(check).model_copy(update={"host_name": host_name})
        waiver = waived_map.get(check.id)
        if waiver is not None:
            payload = payload.model_copy(update={"is_waived": True, "waiver_id": waiver.id})
        check_results.append(payload)

    return JobRunDetail(
        id=job_run.id,
        job_id=job_run.job_id,
        status=job_run.status,
        started_at=job_run.started_at,
        finished_at=job_run.finished_at,
        celery_task_id=job_run.celery_task_id,
        error_message=job_run.error_message,
        created_at=job_run.created_at,
        check_results=check_results,
    )


@router.post("/runs/{run_id}/stop", response_model=JobRunRead)
async def stop_job_run(
    run_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> JobRunRead:
    result = await db.execute(select(JobRun).where(JobRun.id == run_id))
    job_run = result.scalar_one_or_none()
    if not job_run:
        raise HTTPException(status_code=404, detail="Job run not found")

    job = await db.get(Job, job_run.job_id)
    assert_can_access(user, job.owner_sub if job else None, detail="Job run not found")

    if job_run.status not in (JobStatus.PENDING, JobStatus.RUNNING):
        raise HTTPException(status_code=409, detail=f"Cannot stop run in status '{job_run.status.value}'")

    if not await cancel_active_run(db, JobRun, run_id):
        await db.refresh(job_run)
        raise HTTPException(
            status_code=409,
            detail=f"Cannot stop run in status '{job_run.status.value}'",
        )
    if job_run.celery_task_id:
        _revoke_celery_task(job_run.celery_task_id)
    await db.flush()
    await db.refresh(job_run)
    await log_audit_event(
        db,
        request,
        user,
        action="job.stop",
        resource_type="job",
        resource_id=job_run.job_id,
        metadata={"run_id": job_run.id},
    )
    return JobRunRead.model_validate(job_run)


@router.delete("/runs/{run_id}", status_code=204)
async def delete_job_run(
    run_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> None:
    result = await db.execute(
        select(JobRun).options(selectinload(JobRun.check_results)).where(JobRun.id == run_id)
    )
    job_run = result.scalar_one_or_none()
    if not job_run:
        raise HTTPException(status_code=404, detail="Job run not found")

    job = await db.get(Job, job_run.job_id)
    assert_can_access(user, job.owner_sub if job else None, detail="Job run not found")

    if job_run.status in (JobStatus.PENDING, JobStatus.RUNNING):
        if job_run.celery_task_id:
            _revoke_celery_task(job_run.celery_task_id)
        raise HTTPException(status_code=409, detail="Stop the run before deleting it")

    for check in list(job_run.check_results):
        await db.delete(check)
    await db.delete(job_run)


@router.delete("/{job_id}", status_code=204)
async def delete_job(
    job_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> None:
    result = await db.execute(
        select(Job)
        .options(
            selectinload(Job.runs).selectinload(JobRun.check_results),
            selectinload(Job.job_hosts),
        )
        .where(Job.id == job_id)
    )
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    assert_can_access(user, job.owner_sub, detail="Job not found")

    for job_run in list(job.runs):
        if job_run.status in (JobStatus.PENDING, JobStatus.RUNNING):
            raise HTTPException(status_code=409, detail="Stop all active runs before deleting the job")
        for check in list(job_run.check_results):
            await db.delete(check)
        await db.delete(job_run)

    for jh in list(job.job_hosts):
        await db.delete(jh)

    job_name = job.name
    await db.delete(job)
    await log_audit_event(
        db,
        request,
        user,
        action="job.delete",
        resource_type="job",
        resource_id=job_id,
        resource_name=job_name,
    )
