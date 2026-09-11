from fastapi import APIRouter, Request, Response

from app.core.blocking import run_blocking
from app.core.config import settings
from app.middleware.observability import PROMETHEUS_CONTENT_TYPE, render_prometheus_metrics
from app.services.observability_auth import require_observability_token

router = APIRouter()


@router.get("/metrics")
async def metrics(request: Request) -> Response:
    require_observability_token(
        request,
        configured_token=settings.metrics_bearer_token,
        endpoint_name="metrics",
        require_in_production=True,
    )
    content = await run_blocking(
        render_prometheus_metrics,
        timeout=min(
            settings.blocking_io_timeout_seconds,
            settings.metrics_scrape_timeout_seconds,
        ),
    )
    return Response(content=content, media_type=PROMETHEUS_CONTENT_TYPE)
