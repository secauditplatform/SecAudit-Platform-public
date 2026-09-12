from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from secaudit_core.celery_dispatch import revoke_task
from secaudit_core.notifications import enqueue_run_notification, events_for_terminal_status

from app.services.dispatch import (
    cancel_active_run,
    commit_and_try_dispatch,
    correlation_from_request,
    enqueue_run_dispatch,
)

from app.core.auth import AuthUser, require_roles
from app.core.roles import require_remediation
from app.core.config import settings
from app.core.database import get_db
from app.models import (
    CheckScript,
    Job,
    JobStatus,
    RemediationJob,
    RemediationJobHost,
    RemediationResult,
    RemediationRun,
    ScriptKind,
    Profile,
    JobScope,
    UserRole,
)
from app.pagination import paginate_scalars, pagination_params
from app.schemas import (
    PaginatedResponse,
    RemediationFromRunRequest,
    RemediationFromRunResponse,
    RemediationJobCreate,
    RemediationJobRead,
    RemediationJobUpdate,
    RemediationRunDetail,
    RemediationRunRead,
)
from app.services.audit_log import log_audit_event
from app.services.job_webhooks import apply_webhook_fields, webhook_read_fields
from app.services.object_rbac import (
    apply_owner_scope,
    assert_can_access,
    assert_can_mutate,
    assert_hosts_accessible,
    assign_host_target_scope,
    assign_owner,
)
from app.services.network_jobs import validate_job_scope
from app.services.remediation_workflow import build_remediation_suggestion

router = APIRouter()


def _revoke_celery_task(task_id: str) -> None:
    revoke_task(task_id, broker_url=settings.celery_broker_url)


def _remediation_job_to_read(job: RemediationJob) -> RemediationJobRead:
    return RemediationJobRead(
        id=job.id,
        name=job.name,
        profile_id=job.profile_id,
        remediation_script_id=job.remediation_script_id,
        execution_type=job.execution_type,
        scope=job.scope,
        dynamic_filter=job.dynamic_filter,
        cron_expression=job.cron_expression,
        is_scheduled=job.is_scheduled,
        is_active=job.is_active,
        created_at=job.created_at,
        owner_sub=job.owner_sub,
        host_ids=[jh.host_id for jh in job.job_hosts],
        **webhook_read_fields(job),
    )


async def _validate_remediation_script(
    db: AsyncSession,
    profile_id: int,
    remediation_script_id: int | None,
) -> None:
    if remediation_script_id is None:
        return
    script = await db.get(CheckScript, remediation_script_id)
    if not script or script.profile_id != profile_id or script.script_kind != ScriptKind.REMEDIATION:
        raise HTTPException(status_code=400, detail="Invalid remediation script for profile")


@router.get("", response_model=list[RemediationJobRead])
async def list_remediation_jobs(
    scope: JobScope | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_remediation),
) -> list[RemediationJobRead]:
    stmt = (
        select(RemediationJob)
        .options(selectinload(RemediationJob.job_hosts))
        .order_by(RemediationJob.created_at.desc())
    )
    if scope is not None:
        stmt = stmt.where(RemediationJob.scope == scope)
    stmt = apply_owner_scope(stmt, RemediationJob.owner_sub, user)
    result = await db.execute(stmt)
    return [_remediation_job_to_read(job) for job in result.scalars().all()]


@router.post("", response_model=RemediationJobRead, status_code=201)
async def create_remediation_job(
    data: RemediationJobCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> RemediationJobRead:
    profile = await db.get(Profile, data.profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")

    await _validate_remediation_script(db, data.profile_id, data.remediation_script_id)
    await validate_job_scope(
        db,
        scope=data.scope,
        profile_id=data.profile_id,
        host_ids=data.host_ids,
    )
    job = RemediationJob(**data.model_dump(exclude={"host_ids", "webhook_url", "webhook_enabled", "webhook_events"}))
    try:
        apply_webhook_fields(
            job,
            settings=settings,
            webhook_enabled=data.webhook_enabled,
            webhook_events=data.webhook_events,
            webhook_url=data.webhook_url,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    assign_owner(job, user)
    assign_host_target_scope(job, user)
    db.add(job)
    await db.flush()

    await assert_hosts_accessible(db, user, data.host_ids)
    for host_id in data.host_ids:
        db.add(RemediationJobHost(remediation_job_id=job.id, host_id=host_id))

    await db.flush()
    result = await db.execute(
        select(RemediationJob)
        .options(selectinload(RemediationJob.job_hosts))
        .where(RemediationJob.id == job.id)
    )
    await log_audit_event(
        db,
        request,
        user,
        action="remediation.create",
        resource_type="remediation",
        resource_id=job.id,
        resource_name=job.name,
    )
    return _remediation_job_to_read(result.scalar_one())


@router.post("/from-run", response_model=RemediationFromRunResponse, status_code=201)
async def create_remediation_from_run(
    data: RemediationFromRunRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> RemediationFromRunResponse:
    suggestion = await build_remediation_suggestion(db, user, data.source_run_id)
    if suggestion["failed_count"] == 0:
        raise HTTPException(status_code=400, detail="No failed checks to remediate")
    if not suggestion["host_ids"]:
        raise HTTPException(status_code=400, detail="No target hosts for remediation")

    script_id = data.remediation_script_id or suggestion["default_remediation_script_id"]
    await _validate_remediation_script(db, suggestion["profile_id"], script_id)

    baseline_run_id: int | None = None
    if data.set_baseline:
        audit_job = await db.get(Job, suggestion["source_job_id"])
        if audit_job:
            audit_job.baseline_run_id = data.source_run_id
            baseline_run_id = data.source_run_id

    source_job = await db.get(Job, suggestion["source_job_id"])
    remediation_scope = source_job.scope if source_job else JobScope.STANDARD
    await validate_job_scope(
        db,
        scope=remediation_scope,
        profile_id=suggestion["profile_id"],
        host_ids=suggestion["host_ids"],
    )

    job = RemediationJob(
        name=data.name or suggestion["suggested_name"],
        profile_id=suggestion["profile_id"],
        remediation_script_id=script_id,
        execution_type=suggestion["default_execution_type"],
        scope=remediation_scope,
        is_active=True,
    )
    assign_owner(job, user)
    assign_host_target_scope(job, user)
    db.add(job)
    await db.flush()

    await assert_hosts_accessible(db, user, suggestion["host_ids"])
    for host_id in suggestion["host_ids"]:
        db.add(RemediationJobHost(remediation_job_id=job.id, host_id=host_id))

    remediation_run_id: int | None = None
    if data.run_remediation:
        remediation_run = RemediationRun(
            remediation_job_id=job.id,
            status=JobStatus.PENDING,
        )
        db.add(remediation_run)
        await db.flush()

        outbox = await enqueue_run_dispatch(
            db,
            task_name="app.tasks.run_remediation_job",
            args=[remediation_run.id],
            queue="remediation",
            callback_kind="remediation_run",
            callback_ref_id=remediation_run.id,
            correlation=correlation_from_request(
                request, run_kind="remediation", run_id=remediation_run.id
            ),
        )
        await commit_and_try_dispatch(db, outbox_id=outbox.id, pending_entity=remediation_run)

        if remediation_run.status == JobStatus.FAILED:
            raise HTTPException(
                status_code=503,
                detail=remediation_run.error_message or "Failed to dispatch Celery task",
            )

        remediation_run_id = remediation_run.id
        await db.flush()
    else:
        await db.flush()

    await log_audit_event(
        db,
        request,
        user,
        action="remediation.from_run",
        resource_type="remediation",
        resource_id=job.id,
        resource_name=job.name,
        metadata={
            "source_run_id": data.source_run_id,
            "source_job_id": suggestion["source_job_id"],
            "remediation_run_id": remediation_run_id,
        },
    )
    await db.commit()

    return RemediationFromRunResponse(
        remediation_job_id=job.id,
        remediation_run_id=remediation_run_id,
        baseline_run_id=baseline_run_id,
        source_run_id=data.source_run_id,
        source_job_id=suggestion["source_job_id"],
    )


@router.patch("/{job_id}", response_model=RemediationJobRead)
async def update_remediation_job(
    job_id: int,
    data: RemediationJobUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> RemediationJobRead:
    result = await db.execute(
        select(RemediationJob)
        .options(selectinload(RemediationJob.job_hosts))
        .where(RemediationJob.id == job_id)
    )
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Remediation job not found")
    assert_can_mutate(user, job.owner_sub, detail="Remediation job not found")

    updates = data.model_dump(exclude_unset=True)
    host_ids = updates.pop("host_ids", None)
    webhook_url = updates.pop("webhook_url", None)
    clear_webhook_url = updates.pop("clear_webhook_url", None)
    webhook_enabled = updates.pop("webhook_enabled", None)
    webhook_events = updates.pop("webhook_events", None)
    profile_id = updates.get("profile_id", job.profile_id)
    remediation_script_id = updates.get("remediation_script_id", job.remediation_script_id)

    if "profile_id" in updates or "remediation_script_id" in updates:
        await _validate_remediation_script(db, profile_id, remediation_script_id)

    merged_scope = updates.get("scope", job.scope)
    merged_host_ids = host_ids if host_ids is not None else [jh.host_id for jh in job.job_hosts]
    await validate_job_scope(
        db,
        scope=merged_scope,
        profile_id=profile_id,
        host_ids=merged_host_ids,
    )

    for field, value in updates.items():
        setattr(job, field, value)

    try:
        apply_webhook_fields(
            job,
            settings=settings,
            webhook_enabled=webhook_enabled,
            webhook_events=webhook_events,
            webhook_url=webhook_url,
            clear_webhook_url=clear_webhook_url,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if host_ids is not None:
        await assert_hosts_accessible(db, user, host_ids)
        for jh in list(job.job_hosts):
            await db.delete(jh)
        for host_id in host_ids:
            db.add(RemediationJobHost(remediation_job_id=job.id, host_id=host_id))

    await db.flush()
    result = await db.execute(
        select(RemediationJob)
        .options(selectinload(RemediationJob.job_hosts))
        .where(RemediationJob.id == job.id)
    )
    await log_audit_event(
        db,
        request,
        user,
        action="remediation.update",
        resource_type="remediation",
        resource_id=job.id,
        resource_name=job.name,
    )
    return _remediation_job_to_read(result.scalar_one())


@router.get("/runs", response_model=PaginatedResponse[RemediationRunRead])
async def list_remediation_runs(
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_remediation),
    page: tuple[int, int] = Depends(pagination_params),
) -> PaginatedResponse[RemediationRunRead]:
    offset, limit = page
    stmt = select(RemediationRun).join(
        RemediationJob, RemediationJob.id == RemediationRun.remediation_job_id
    )
    stmt = apply_owner_scope(stmt, RemediationJob.owner_sub, user)
    stmt = stmt.order_by(RemediationRun.created_at.desc())
    runs, total = await paginate_scalars(db, stmt, offset=offset, limit=limit)
    return PaginatedResponse(
        items=[RemediationRunRead.model_validate(run) for run in runs],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.post("/{job_id}/run", response_model=RemediationRunRead, status_code=201)
async def run_remediation_job(
    job_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> RemediationRunRead:
    result = await db.execute(select(RemediationJob).where(RemediationJob.id == job_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Remediation job not found")
    assert_can_mutate(user, job.owner_sub, detail="Remediation job not found")

    remediation_run = RemediationRun(
        remediation_job_id=job.id,
        status=JobStatus.PENDING,
    )
    db.add(remediation_run)
    await db.flush()

    outbox = await enqueue_run_dispatch(
        db,
        task_name="app.tasks.run_remediation_job",
        args=[remediation_run.id],
        queue="remediation",
        callback_kind="remediation_run",
        callback_ref_id=remediation_run.id,
        correlation=correlation_from_request(
            request, run_kind="remediation", run_id=remediation_run.id
        ),
    )
    await commit_and_try_dispatch(db, outbox_id=outbox.id, pending_entity=remediation_run)

    if remediation_run.status == JobStatus.FAILED:
        exc = RuntimeError(remediation_run.error_message or "Failed to dispatch Celery task")
        await log_audit_event(
            db,
            request,
            user,
            action="remediation.run",
            resource_type="remediation",
            resource_id=job.id,
            resource_name=job.name,
            outcome="failed",
            metadata={"run_id": remediation_run.id, "error": str(exc)},
        )
        await db.commit()
        enqueue_run_notification(
            broker_url=settings.celery_broker_url,
            settings=settings,
            trigger_events=events_for_terminal_status(JobStatus.FAILED, source="dispatch"),
            run_kind="remediation",
            run_id=remediation_run.id,
            job_id=job.id,
            job_name=job.name,
            status=JobStatus.FAILED.value,
            error_message=str(exc),
            owner_sub=job.owner_sub,
        )
        await db.refresh(remediation_run)
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    await db.flush()
    await db.refresh(remediation_run)
    await log_audit_event(
        db,
        request,
        user,
        action="remediation.run",
        resource_type="remediation",
        resource_id=job.id,
        resource_name=job.name,
        metadata={"run_id": remediation_run.id},
    )
    return RemediationRunRead.model_validate(remediation_run)


@router.get("/runs/{run_id}", response_model=RemediationRunDetail)
async def get_remediation_run(
    run_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_remediation),
) -> RemediationRunDetail:
    result = await db.execute(
        select(RemediationRun)
        .options(selectinload(RemediationRun.results))
        .where(RemediationRun.id == run_id)
    )
    remediation_run = result.scalar_one_or_none()
    if not remediation_run:
        raise HTTPException(status_code=404, detail="Remediation run not found")
    job = await db.get(RemediationJob, remediation_run.remediation_job_id)
    assert_can_access(user, job.owner_sub if job else None, detail="Remediation run not found")
    return RemediationRunDetail.model_validate(remediation_run)


@router.post("/runs/{run_id}/stop", response_model=RemediationRunRead)
async def stop_remediation_run(
    run_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> RemediationRunRead:
    result = await db.execute(select(RemediationRun).where(RemediationRun.id == run_id))
    remediation_run = result.scalar_one_or_none()
    if not remediation_run:
        raise HTTPException(status_code=404, detail="Remediation run not found")

    job = await db.get(RemediationJob, remediation_run.remediation_job_id)
    assert_can_mutate(user, job.owner_sub if job else None, detail="Remediation run not found")

    if remediation_run.status not in (JobStatus.PENDING, JobStatus.RUNNING):
        raise HTTPException(
            status_code=409, detail=f"Cannot stop run in status '{remediation_run.status.value}'"
        )

    if not await cancel_active_run(db, RemediationRun, run_id):
        await db.refresh(remediation_run)
        raise HTTPException(
            status_code=409,
            detail=f"Cannot stop run in status '{remediation_run.status.value}'",
        )
    if remediation_run.celery_task_id:
        _revoke_celery_task(remediation_run.celery_task_id)
    await db.flush()
    await db.refresh(remediation_run)
    await log_audit_event(
        db,
        request,
        user,
        action="remediation.stop",
        resource_type="remediation",
        resource_id=remediation_run.remediation_job_id,
        metadata={"run_id": remediation_run.id},
    )
    return RemediationRunRead.model_validate(remediation_run)


@router.delete("/runs/{run_id}", status_code=204)
async def delete_remediation_run(
    run_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> None:
    result = await db.execute(
        select(RemediationRun)
        .options(selectinload(RemediationRun.results))
        .where(RemediationRun.id == run_id)
    )
    remediation_run = result.scalar_one_or_none()
    if not remediation_run:
        raise HTTPException(status_code=404, detail="Remediation run not found")

    job = await db.get(RemediationJob, remediation_run.remediation_job_id)
    assert_can_mutate(user, job.owner_sub if job else None, detail="Remediation run not found")

    if remediation_run.status in (JobStatus.PENDING, JobStatus.RUNNING):
        if remediation_run.celery_task_id:
            _revoke_celery_task(remediation_run.celery_task_id)
        raise HTTPException(status_code=409, detail="Stop the run before deleting it")

    for item in list(remediation_run.results):
        await db.delete(item)
    await db.delete(remediation_run)


@router.delete("/{job_id}", status_code=204)
async def delete_remediation_job(
    job_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> None:
    result = await db.execute(
        select(RemediationJob)
        .options(
            selectinload(RemediationJob.runs).selectinload(RemediationRun.results),
            selectinload(RemediationJob.job_hosts),
        )
        .where(RemediationJob.id == job_id)
    )
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Remediation job not found")
    assert_can_mutate(user, job.owner_sub, detail="Remediation job not found")

    for remediation_run in list(job.runs):
        if remediation_run.status in (JobStatus.PENDING, JobStatus.RUNNING):
            raise HTTPException(
                status_code=409, detail="Stop all active runs before deleting the remediation job"
            )
        for item in list(remediation_run.results):
            await db.delete(item)
        await db.delete(remediation_run)

    for jh in list(job.job_hosts):
        await db.delete(jh)

    job_name = job.name
    await db.delete(job)
    await log_audit_event(
        db,
        request,
        user,
        action="remediation.delete",
        resource_type="remediation",
        resource_id=job_id,
        resource_name=job_name,
    )
