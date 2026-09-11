from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import AuthUser, require_roles
from app.core.database import get_db
from app.models import AuditLog, UserRole
from app.pagination import paginate_scalars, pagination_params
from app.schemas import (
    AuditLogRead,
    AuditMetricPoint,
    AuditOverviewRead,
    AuditTimelinePoint,
    PaginatedResponse,
)
from secaudit_core.sensitive_data import redact_sensitive

router = APIRouter()


@router.get("", response_model=PaginatedResponse[AuditLogRead])
async def list_audit_logs(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
    page: tuple[int, int] = Depends(pagination_params),
    action: str | None = Query(default=None),
    resource_type: str | None = Query(default=None),
    actor_username: str | None = Query(default=None),
    outcome: str | None = Query(default=None),
    from_datetime: datetime | None = Query(default=None, alias="from"),
    to_datetime: datetime | None = Query(default=None, alias="to"),
) -> PaginatedResponse[AuditLogRead]:
    offset, limit = page
    stmt = select(AuditLog)
    if action:
        stmt = stmt.where(AuditLog.action == action)
    if resource_type:
        stmt = stmt.where(AuditLog.resource_type == resource_type)
    if actor_username:
        stmt = stmt.where(AuditLog.actor_username == actor_username)
    if outcome:
        stmt = stmt.where(AuditLog.outcome == outcome)
    if from_datetime:
        stmt = stmt.where(AuditLog.created_at >= from_datetime)
    if to_datetime:
        stmt = stmt.where(AuditLog.created_at <= to_datetime)
    stmt = stmt.order_by(AuditLog.created_at.desc())
    rows, total = await paginate_scalars(db, stmt, offset=offset, limit=limit)
    return PaginatedResponse(
        items=[
            AuditLogRead.model_validate(item).model_copy(
                update={"metadata_json": redact_sensitive(item.metadata_json)}
            )
            for item in rows
        ],
        total=total,
        offset=offset,
        limit=limit,
    )


@router.get("/overview", response_model=AuditOverviewRead)
async def get_audit_overview(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
    days: int = Query(default=14, ge=1, le=365),
    top: int = Query(default=8, ge=1, le=20),
) -> AuditOverviewRead:
    window_start = datetime.now(UTC) - timedelta(days=days)
    base_filter = AuditLog.created_at >= window_start

    total_stmt = select(func.count(AuditLog.id)).where(base_filter)
    total_events = int((await db.execute(total_stmt)).scalar_one() or 0)

    day_bucket = func.date_trunc("day", AuditLog.created_at).label("day")
    timeline_stmt = (
        select(day_bucket, func.count(AuditLog.id))
        .where(base_filter)
        .group_by(day_bucket)
        .order_by(day_bucket)
    )
    timeline_rows = (await db.execute(timeline_stmt)).all()
    events_over_time = [
        AuditTimelinePoint(day=day.isoformat()[:10], count=count)
        for day, count in timeline_rows
        if day is not None
    ]

    action_stmt = (
        select(AuditLog.action, func.count(AuditLog.id).label("count"))
        .where(base_filter)
        .group_by(AuditLog.action)
        .order_by(func.count(AuditLog.id).desc(), AuditLog.action.asc())
        .limit(top)
    )
    actor_stmt = (
        select(AuditLog.actor_username, func.count(AuditLog.id).label("count"))
        .where(base_filter)
        .group_by(AuditLog.actor_username)
        .order_by(func.count(AuditLog.id).desc(), AuditLog.actor_username.asc())
        .limit(top)
    )
    outcome_stmt = (
        select(AuditLog.outcome, func.count(AuditLog.id).label("count"))
        .where(base_filter)
        .group_by(AuditLog.outcome)
        .order_by(func.count(AuditLog.id).desc(), AuditLog.outcome.asc())
    )
    resource_stmt = (
        select(AuditLog.resource_type, func.count(AuditLog.id).label("count"))
        .where(base_filter)
        .group_by(AuditLog.resource_type)
        .order_by(func.count(AuditLog.id).desc(), AuditLog.resource_type.asc())
        .limit(top)
    )

    top_actions = [
        AuditMetricPoint(label=label, count=count) for label, count in (await db.execute(action_stmt)).all()
    ]
    top_actors = [
        AuditMetricPoint(label=label, count=count) for label, count in (await db.execute(actor_stmt)).all()
    ]
    outcomes = [
        AuditMetricPoint(label=label, count=count) for label, count in (await db.execute(outcome_stmt)).all()
    ]
    resource_types = [
        AuditMetricPoint(label=label, count=count) for label, count in (await db.execute(resource_stmt)).all()
    ]

    return AuditOverviewRead(
        total_events=total_events,
        period_days=days,
        events_over_time=events_over_time,
        top_actions=top_actions,
        top_actors=top_actors,
        outcomes=outcomes,
        resource_types=resource_types,
    )
