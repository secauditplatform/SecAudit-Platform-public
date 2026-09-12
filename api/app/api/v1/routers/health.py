from fastapi import APIRouter, Request, Response, status

from app.core.config import settings
from app.schemas import HealthResponse, ReadinessResponse
from app.services.health_checks import gather_readiness_components
from app.services.observability_auth import require_observability_token

router = APIRouter()


@router.get("/health", response_model=HealthResponse)
async def health_check() -> HealthResponse:
    """Liveness probe — quick ok without dependency checks."""
    return HealthResponse(
        status="ok",
        app_name=settings.app_name,
        version=settings.app_version,
        demo_mode=settings.demo_mode,
    )


@router.get("/health/live", response_model=HealthResponse)
async def liveness_check() -> HealthResponse:
    return HealthResponse(
        status="ok",
        app_name=settings.app_name,
        version=settings.app_version,
        demo_mode=settings.demo_mode,
    )


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
