from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import create_engine, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from app.core.auth import AuthUser, require_roles
from app.core.blocking import run_blocking
from app.core.config import settings
from app.core.database import get_db
from app.core.secrets import encrypt_secret
from app.models import Job, ScheduledReport, UserRole
from app.schemas import (
    ScheduledReportCreate,
    ScheduledReportDeliverResponse,
    ScheduledReportRead,
    ScheduledReportUpdate,
)
from app.services.audit_log import log_audit_event
from app.services.object_rbac import apply_owner_scope, assert_job_access
from secaudit_core.scheduled_reports import deliver_scheduled_report
from secaudit_core.sensitive_data import redact_sensitive

router = APIRouter()
_delivery_engine = create_engine(settings.database_url_sync, pool_pre_ping=True)
_DeliverySession = sessionmaker(_delivery_engine, expire_on_commit=False)


def _schedule_to_read(schedule: ScheduledReport) -> ScheduledReportRead:
    return ScheduledReportRead(
        id=schedule.id,
        name=schedule.name,
        job_id=schedule.job_id,
        cron_expression=schedule.cron_expression,
        is_active=schedule.is_active,
        report_format=schedule.report_format,
        delivery_type=schedule.delivery_type,
        config_json=redact_sensitive(schedule.config_json),
        has_secret=bool(schedule.encrypted_secret),
        last_delivered_at=schedule.last_delivered_at,
        last_delivered_run_id=schedule.last_delivered_run_id,
        created_at=schedule.created_at,
        updated_at=schedule.updated_at,
    )


def _encrypt_secret(secret: str | None) -> str | None:
    if not secret:
        return None
    return encrypt_secret(secret, settings)


def _deliver_with_sync_session(schedule_id: int, run_id: int | None) -> dict:
    with _DeliverySession() as sync_db:
        sync_schedule = sync_db.get(ScheduledReport, schedule_id)
        if sync_schedule is None:
            return {"delivered": False, "reason": "schedule_not_found"}
        result = deliver_scheduled_report(
            sync_db, sync_schedule, settings, run_id=run_id, manual=True
        )
        sync_db.commit()
        return result


@router.get("", response_model=list[ScheduledReportRead])
async def list_scheduled_reports(
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN, UserRole.OPERATOR)),
) -> list[ScheduledReportRead]:
    stmt = select(ScheduledReport).join(Job, ScheduledReport.job_id == Job.id)
    stmt = apply_owner_scope(stmt, Job.owner_sub, user).order_by(ScheduledReport.name)
    result = await db.execute(stmt)
    return [_schedule_to_read(item) for item in result.scalars().all()]


@router.post("", response_model=ScheduledReportRead, status_code=201)
async def create_scheduled_report(
    data: ScheduledReportCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN, UserRole.OPERATOR)),
) -> ScheduledReportRead:
    existing = await db.execute(select(ScheduledReport).where(ScheduledReport.name == data.name))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Scheduled report with this name already exists")

    await assert_job_access(db, user, data.job_id)

    schedule = ScheduledReport(
        name=data.name,
        job_id=data.job_id,
        cron_expression=data.cron_expression,
        is_active=data.is_active,
        report_format=data.report_format,
        delivery_type=data.delivery_type,
        config_json=data.config_json,
        encrypted_secret=_encrypt_secret(data.secret),
    )
    db.add(schedule)
    await db.flush()
    await db.refresh(schedule)
    await log_audit_event(
        db,
        request,
        user,
        action="scheduled_report.create",
        resource_type="scheduled_report",
        resource_id=schedule.id,
        resource_name=schedule.name,
    )
    return _schedule_to_read(schedule)


@router.get("/{schedule_id}", response_model=ScheduledReportRead)
async def get_scheduled_report(
    schedule_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN, UserRole.OPERATOR)),
) -> ScheduledReportRead:
    schedule = await db.get(ScheduledReport, schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Scheduled report not found")
    await assert_job_access(db, user, schedule.job_id)
    return _schedule_to_read(schedule)


@router.patch("/{schedule_id}", response_model=ScheduledReportRead)
async def update_scheduled_report(
    schedule_id: int,
    data: ScheduledReportUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN, UserRole.OPERATOR)),
) -> ScheduledReportRead:
    schedule = await db.get(ScheduledReport, schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Scheduled report not found")
    await assert_job_access(db, user, schedule.job_id)

    if data.name is not None and data.name != schedule.name:
        existing = await db.execute(select(ScheduledReport).where(ScheduledReport.name == data.name))
        if existing.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Scheduled report with this name already exists")
        schedule.name = data.name

    if data.job_id is not None:
        await assert_job_access(db, user, data.job_id)
        schedule.job_id = data.job_id
    if data.cron_expression is not None:
        schedule.cron_expression = data.cron_expression
    if data.is_active is not None:
        schedule.is_active = data.is_active
    if data.report_format is not None:
        schedule.report_format = data.report_format
    if data.delivery_type is not None:
        schedule.delivery_type = data.delivery_type
    if data.config_json is not None:
        schedule.config_json = data.config_json
    if data.secret:
        schedule.encrypted_secret = _encrypt_secret(data.secret)

    await db.flush()
    await db.refresh(schedule)
    await log_audit_event(
        db,
        request,
        user,
        action="scheduled_report.update",
        resource_type="scheduled_report",
        resource_id=schedule.id,
        resource_name=schedule.name,
    )
    return _schedule_to_read(schedule)


@router.delete("/{schedule_id}", status_code=204)
async def delete_scheduled_report(
    schedule_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN, UserRole.OPERATOR)),
) -> None:
    schedule = await db.get(ScheduledReport, schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Scheduled report not found")
    await assert_job_access(db, user, schedule.job_id)

    schedule_name = schedule.name
    await db.delete(schedule)
    await log_audit_event(
        db,
        request,
        user,
        action="scheduled_report.delete",
        resource_type="scheduled_report",
        resource_id=schedule_id,
        resource_name=schedule_name,
    )


@router.post("/{schedule_id}/deliver", response_model=ScheduledReportDeliverResponse)
async def deliver_scheduled_report_now(
    schedule_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN, UserRole.OPERATOR)),
    run_id: int | None = None,
) -> ScheduledReportDeliverResponse:
    schedule = await db.get(ScheduledReport, schedule_id)
    if not schedule:
        raise HTTPException(status_code=404, detail="Scheduled report not found")
    await assert_job_access(db, user, schedule.job_id)

    try:
        result = await run_blocking(
            _deliver_with_sync_session,
            schedule_id,
            run_id,
            timeout=settings.blocking_io_timeout_seconds,
        )
    except Exception as exc:
        safe_error = redact_sensitive(str(exc))
        await log_audit_event(
            db,
            request,
            user,
            action="scheduled_report.deliver",
            resource_type="scheduled_report",
            resource_id=schedule.id,
            resource_name=schedule.name,
            outcome="failed",
            metadata={"error": safe_error},
        )
        raise HTTPException(status_code=502, detail=safe_error) from exc

    await db.refresh(schedule)
    await log_audit_event(
        db,
        request,
        user,
        action="scheduled_report.deliver",
        resource_type="scheduled_report",
        resource_id=schedule.id,
        resource_name=schedule.name,
        outcome="success" if result.get("delivered") else "skipped",
        metadata=result,
    )
    return ScheduledReportDeliverResponse(**result)
