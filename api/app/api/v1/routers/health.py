import asyncio

from fastapi import APIRouter, Depends, Request, Response, status

from app.core.auth import AuthUser, require_roles
from app.core.config import settings
from app.core.database import get_db
from app.models import UserRole
from app.schemas import (
    ComponentHealth,
    HealthResponse,
    ReadinessResponse,
    SystemHealthResponse,
    SystemHealthSettingsRead,
    SystemHealthSettingsUpdate,
)
from app.services.audit_log import log_audit_event
from app.services.health_checks import (
    check_postgres,
    check_redis,
    gather_readiness_components,
)
from app.services.observability_auth import require_observability_token
from secaudit_core.celery_observability import (
    beat_heartbeat_age_seconds,
    queue_depths,
    worker_heartbeat_age_seconds,
)
from secaudit_core.runtime_settings import get_job_run_retention_days, set_job_run_retention_days
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Liveness probe — quick ok without dependency checks."""
    return HealthResponse(status="ok", app_name=settings.app_name)


@router.get("/health/live", response_model=HealthResponse)
async def liveness_check() -> HealthResponse:
    return HealthResponse(status="ok", app_name=settings.app_name)


@router.get("/health/ready", response_model=ReadinessResponse)
async def readiness_check(request: Request, response: Response) -> ReadinessResponse:
    require_observability_token(
        request,
        configured_token=settings.readiness_bearer_token,
        endpoint_name="readiness",
        require_in_production=False,
    )
    components = await gather_readiness_components()
    all_ok = all(component.status == "ok" for component in components.values())
    if not all_ok:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return ReadinessResponse(
        status="ok" if all_ok else "error",
        app_name=settings.app_name,
        components=components,
    )


def _heartbeat_component(age: float | None, *, max_age: int, missing: str) -> ComponentHealth:
    if age is None:
        return ComponentHealth(status="error", detail=missing)
    if age > max_age:
        return ComponentHealth(
            status="error",
            detail=f"stale ({int(age)}s > {max_age}s)",
        )
    return ComponentHealth(status="ok", detail=f"{int(age)}s ago")


def _effective_retention_days() -> int:
    return get_job_run_retention_days(
        settings.redis_url,
        env_default=settings.job_run_retention_days,
    )


@router.get("/health/system", response_model=SystemHealthResponse)
async def system_health(
    _: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> SystemHealthResponse:
    """Admin panel: dependency status, beat/worker heartbeats, Celery queue depths."""
    postgres, redis = await asyncio.gather(check_postgres(), check_redis())
    worker_age = await asyncio.to_thread(worker_heartbeat_age_seconds, settings.redis_url)
    beat_age = await asyncio.to_thread(beat_heartbeat_age_seconds, settings.redis_url)
    depths = await asyncio.to_thread(queue_depths, settings.redis_url)
    retention_days = await asyncio.to_thread(_effective_retention_days)

    beat_max_age = max(180, int(settings.beat_lock_ttl_seconds) * 3)
    components = {
        "postgres": postgres,
        "redis": redis,
        "worker": _heartbeat_component(
            worker_age,
            max_age=settings.worker_heartbeat_max_age_seconds,
            missing="worker heartbeat missing",
        ),
        "beat": _heartbeat_component(
            beat_age,
            max_age=beat_max_age,
            missing="beat heartbeat missing (no recent scheduled maintenance)",
        ),
    }
    all_ok = all(component.status == "ok" for component in components.values())
    return SystemHealthResponse(
        status="ok" if all_ok else "error",
        components=components,
        queues=depths,
        retention_days=retention_days,
    )


@router.patch("/health/system/settings", response_model=SystemHealthSettingsRead)
async def update_system_health_settings(
    payload: SystemHealthSettingsUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> SystemHealthSettingsRead:
    previous = await asyncio.to_thread(_effective_retention_days)
    retention_days = await asyncio.to_thread(
        set_job_run_retention_days,
        settings.redis_url,
        payload.retention_days,
    )
    await log_audit_event(
        db,
        request,
        user,
        action="system.retention.update",
        resource_type="system",
        resource_id="job_run_retention_days",
        metadata={"previous": previous, "retention_days": retention_days},
    )
    return SystemHealthSettingsRead(retention_days=retention_days)
