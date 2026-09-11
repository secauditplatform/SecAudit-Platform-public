from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.v1.routers.jobs import _job_to_read
from app.services.dispatch import (
    commit_and_try_dispatch,
    correlation_from_request,
    enqueue_run_dispatch,
)
from app.core.auth import AuthUser, require_roles
from app.core.roles import require_operate
from app.core.config import settings
from app.core.database import get_db
from app.models import Host, Job, JobHost, JobRun, JobStatus, JobTemplate, JobTemplateHost, Playbook, Profile, UserRole
from app.schemas import (
    DynamicHostFilter,
    JobCreate,
    JobRead,
    JobRunRead,
    JobTemplateApply,
    JobTemplateCreate,
    JobTemplateRead,
    JobTemplateUpdate,
)
from app.services.audit_log import log_audit_event
from app.services.object_rbac import (
    apply_owner_scope,
    assert_can_access,
    assert_hosts_accessible,
    assign_host_target_scope,
    assign_owner,
)
from secaudit_core.notifications import enqueue_run_notification, events_for_terminal_status

router = APIRouter()


def _template_to_read(template: JobTemplate) -> JobTemplateRead:
    return JobTemplateRead(
        id=template.id,
        name=template.name,
        description=template.description,
        profile_id=template.profile_id,
        playbook_id=template.playbook_id,
        execution_type=template.execution_type,
        dynamic_filter=template.dynamic_filter,
        cron_expression=template.cron_expression,
        is_scheduled=template.is_scheduled,
        is_active=template.is_active,
        created_at=template.created_at,
        updated_at=template.updated_at,
        host_ids=[link.host_id for link in template.template_hosts],
        profile_name=template.profile.profile_name if template.profile else None,
        playbook_name=template.playbook.name if template.playbook else None,
        owner_sub=template.owner_sub,
    )


async def _get_template(db: AsyncSession, template_id: int) -> JobTemplate | None:
    result = await db.execute(
        select(JobTemplate)
        .options(
            selectinload(JobTemplate.template_hosts),
            selectinload(JobTemplate.profile),
            selectinload(JobTemplate.playbook),
        )
        .where(JobTemplate.id == template_id)
    )
    return result.scalar_one_or_none()


@router.get("", response_model=list[JobTemplateRead])
async def list_job_templates(
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_operate),
) -> list[JobTemplateRead]:
    stmt = (
        select(JobTemplate)
        .options(
            selectinload(JobTemplate.template_hosts),
            selectinload(JobTemplate.profile),
            selectinload(JobTemplate.playbook),
        )
        .order_by(JobTemplate.name)
    )
    stmt = apply_owner_scope(stmt, JobTemplate.owner_sub, user)
    result = await db.execute(stmt)
    return [_template_to_read(item) for item in result.scalars().all()]


@router.post("", response_model=JobTemplateRead, status_code=201)
async def create_job_template(
    data: JobTemplateCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> JobTemplateRead:
    existing = await db.execute(select(JobTemplate).where(JobTemplate.name == data.name))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Job template with this name already exists")

    if data.profile_id:
        profile = await db.get(Profile, data.profile_id)
        if not profile:
            raise HTTPException(status_code=404, detail="Profile not found")
    if data.playbook_id:
        playbook = await db.get(Playbook, data.playbook_id)
        if not playbook:
            raise HTTPException(status_code=404, detail="Playbook not found")

    template = JobTemplate(**data.model_dump(exclude={"host_ids"}))
    assign_owner(template, user)
    db.add(template)
    await db.flush()

    await assert_hosts_accessible(db, user, data.host_ids)
    for host_id in data.host_ids:
        host = await db.get(Host, host_id)
        if not host:
            raise HTTPException(status_code=404, detail=f"Host {host_id} not found")
        db.add(JobTemplateHost(template_id=template.id, host_id=host_id))

    await db.flush()
    saved = await _get_template(db, template.id)
    assert saved is not None
    await log_audit_event(
        db,
        request,
        user,
        action="job_template.create",
        resource_type="job_template",
        resource_id=template.id,
        resource_name=template.name,
    )
    return _template_to_read(saved)


@router.get("/{template_id}", response_model=JobTemplateRead)
async def get_job_template(
    template_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_operate),
) -> JobTemplateRead:
    template = await _get_template(db, template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Job template not found")
    assert_can_access(user, template.owner_sub, detail="Job template not found")
    return _template_to_read(template)


@router.patch("/{template_id}", response_model=JobTemplateRead)
async def update_job_template(
    template_id: int,
    data: JobTemplateUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> JobTemplateRead:
    template = await _get_template(db, template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Job template not found")
    assert_can_access(user, template.owner_sub, detail="Job template not found")

    if data.name is not None and data.name != template.name:
        existing = await db.execute(select(JobTemplate).where(JobTemplate.name == data.name))
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Job template with this name already exists")
        template.name = data.name

    updates = data.model_dump(exclude_unset=True)
    host_ids = updates.pop("host_ids", None)

    for field, value in updates.items():
        setattr(template, field, value)

    if template.profile_id:
        profile = await db.get(Profile, template.profile_id)
        if not profile:
            raise HTTPException(status_code=404, detail="Profile not found")
    if template.playbook_id:
        playbook = await db.get(Playbook, template.playbook_id)
        if not playbook:
            raise HTTPException(status_code=404, detail="Playbook not found")
    if not template.profile_id and not template.playbook_id:
        raise HTTPException(status_code=400, detail="profile_id or playbook_id is required")

    if host_ids is not None:
        await assert_hosts_accessible(db, user, host_ids)
        for link in list(template.template_hosts):
            await db.delete(link)
        for host_id in host_ids:
            db.add(JobTemplateHost(template_id=template.id, host_id=host_id))

    await db.flush()
    saved = await _get_template(db, template.id)
    assert saved is not None
    await log_audit_event(
        db,
        request,
        user,
        action="job_template.update",
        resource_type="job_template",
        resource_id=template.id,
        resource_name=template.name,
    )
    return _template_to_read(saved)


@router.delete("/{template_id}", status_code=204)
async def delete_job_template(
    template_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> None:
    template = await _get_template(db, template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Job template not found")
    assert_can_access(user, template.owner_sub, detail="Job template not found")

    template_name = template.name
    await db.delete(template)
    await log_audit_event(
        db,
        request,
        user,
        action="job_template.delete",
        resource_type="job_template",
        resource_id=template_id,
        resource_name=template_name,
    )


@router.post("/{template_id}/apply", response_model=JobRead)
async def apply_job_template(
    template_id: int,
    data: JobTemplateApply,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> JobRead:
    template = await _get_template(db, template_id)
    if not template:
        raise HTTPException(status_code=404, detail="Job template not found")
    assert_can_access(user, template.owner_sub, detail="Job template not found")
    if not template.is_active:
        raise HTTPException(status_code=409, detail="Job template is inactive")

    host_ids = data.host_ids if data.host_ids is not None else [link.host_id for link in template.template_hosts]
    if host_ids:
        await assert_hosts_accessible(db, user, host_ids)
    if data.dynamic_filter is not None:
        dynamic_filter = data.dynamic_filter
    elif template.dynamic_filter:
        dynamic_filter = DynamicHostFilter.model_validate(template.dynamic_filter)
    else:
        dynamic_filter = None

    job_name = data.name or template.name
    if not host_ids and dynamic_filter is None:
        raise HTTPException(
            status_code=400,
            detail="host_ids or dynamic_filter is required when applying a template",
        )

    job_payload = JobCreate(
        name=job_name,
        profile_id=template.profile_id,
        playbook_id=template.playbook_id,
        execution_type=template.execution_type,
        dynamic_filter=dynamic_filter,
        cron_expression=template.cron_expression if template.is_scheduled else None,
        is_scheduled=template.is_scheduled,
        is_active=True,
        host_ids=host_ids,
    )

    job = Job(**job_payload.model_dump(exclude={"host_ids"}))
    assign_owner(job, user)
    assign_host_target_scope(job, user)
    db.add(job)
    await db.flush()

    for host_id in job_payload.host_ids:
        db.add(JobHost(job_id=job.id, host_id=host_id))

    await db.flush()
    result = await db.execute(select(Job).options(selectinload(Job.job_hosts)).where(Job.id == job.id))
    created_job = result.scalar_one()

    await log_audit_event(
        db,
        request,
        user,
        action="job_template.apply",
        resource_type="job_template",
        resource_id=template.id,
        resource_name=template.name,
        metadata={"job_id": created_job.id, "job_name": created_job.name},
    )

    if data.run_after_create:
        job_run = JobRun(job_id=created_job.id, status=JobStatus.PENDING)
        db.add(job_run)
        await db.flush()

        outbox = await enqueue_run_dispatch(
            db,
            task_name="app.tasks.run_compliance_job",
            args=[job_run.id],
            queue="compliance",
            callback_kind="job_run",
            callback_ref_id=job_run.id,
            correlation=correlation_from_request(
                request, run_kind="job", run_id=job_run.id
            ),
        )
        await commit_and_try_dispatch(db, outbox_id=outbox.id, pending_entity=job_run)

        if job_run.status == JobStatus.FAILED:
            exc = RuntimeError(job_run.error_message or "Failed to dispatch Celery task")
            enqueue_run_notification(
                broker_url=settings.celery_broker_url,
                settings=settings,
                trigger_events=events_for_terminal_status(JobStatus.FAILED, source="dispatch"),
                run_kind="job",
                run_id=job_run.id,
                job_id=created_job.id,
                job_name=created_job.name,
                status=JobStatus.FAILED.value,
                error_message=str(exc),
                owner_sub=created_job.owner_sub,
            )
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        await db.flush()

    return _job_to_read(created_job)
