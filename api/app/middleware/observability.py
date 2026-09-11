"""HTTP metrics (prometheus-client) and structured access logs."""

from __future__ import annotations

import json
import logging
import time
import uuid

from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from starlette.requests import Request
from starlette.responses import Response

from app.core.config import settings
from secaudit_core.celery_observability import fetch_outbox_stats, render_celery_prometheus_metrics
from secaudit_core.dead_letter import fetch_dlq_stats

access_logger = logging.getLogger("secaudit.access")
_outbox_stats_cache: tuple[float, dict[str, float | None]] | None = None
_dlq_stats_cache: tuple[float, dict[str, float]] | None = None
OUTBOX_STATS_CACHE_TTL_SECONDS = 5.0

HTTP_REQUESTS = Counter(
    "secaudit_http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status"],
)
HTTP_REQUEST_DURATION = Histogram(
    "secaudit_http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "path"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
)
# Compatibility counters for existing scrapes that expect ms sum + count.
HTTP_REQUEST_DURATION_MS_SUM = Counter(
    "secaudit_http_request_duration_ms_sum",
    "Sum of HTTP request durations in milliseconds",
    ["method", "path"],
)
HTTP_REQUEST_DURATION_MS_COUNT = Counter(
    "secaudit_http_request_duration_ms_count",
    "Count of HTTP requests observed for duration",
    ["method", "path"],
)


async def observability_middleware(request: Request, call_next) -> Response:
    request_id = request.headers.get("x-request-id") or uuid.uuid4().hex
    started = time.perf_counter()
    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        response.headers["X-Request-Id"] = request_id
        return response
    finally:
        duration_s = time.perf_counter() - started
        duration_ms = duration_s * 1000
        route = request.scope.get("route")
        path_template = getattr(route, "path", request.url.path)
        method = request.method
        HTTP_REQUESTS.labels(method=method, path=path_template, status=str(status_code)).inc()
        HTTP_REQUEST_DURATION.labels(method=method, path=path_template).observe(duration_s)
        HTTP_REQUEST_DURATION_MS_SUM.labels(method=method, path=path_template).inc(duration_ms)
        HTTP_REQUEST_DURATION_MS_COUNT.labels(method=method, path=path_template).inc()

        access_logger.info(
            json.dumps(
                {
                    "event": "http.request",
                    "request_id": request_id,
                    "method": request.method,
                    "path": request.url.path,
                    "route": path_template,
                    "status_code": status_code,
                    "duration_ms": round(duration_ms, 2),
                },
                ensure_ascii=False,
            )
        )


def _cached_outbox_stats() -> dict[str, float | None] | None:
    global _outbox_stats_cache
    now = time.monotonic()
    if _outbox_stats_cache is not None:
        cached_at, stats = _outbox_stats_cache
        if now - cached_at < OUTBOX_STATS_CACHE_TTL_SECONDS:
            return stats
    try:
        stats = fetch_outbox_stats(settings.database_url_sync)
    except Exception as exc:
        logging.getLogger(__name__).warning("Outbox metrics DB scrape failed: %s", exc)
        return None
    _outbox_stats_cache = (now, stats)
    return stats


def _cached_dlq_stats() -> dict[str, float] | None:
    global _dlq_stats_cache
    now = time.monotonic()
    if _dlq_stats_cache is not None:
        cached_at, stats = _dlq_stats_cache
        if now - cached_at < OUTBOX_STATS_CACHE_TTL_SECONDS:
            return stats
    try:
        stats = fetch_dlq_stats(settings.database_url_sync)
    except Exception as exc:
        logging.getLogger(__name__).warning("DLQ metrics DB scrape failed: %s", exc)
        return None
    _dlq_stats_cache = (now, stats)
    return stats


def render_prometheus_metrics() -> str:
    http_body = generate_latest().decode("utf-8")
    outbox_stats = _cached_outbox_stats()
    dlq_stats = _cached_dlq_stats()

    celery_metrics, scrape_error = render_celery_prometheus_metrics(
        settings.redis_url,
        broker_url=settings.celery_broker_url,
        outbox_stats=outbox_stats,
        dlq_stats=dlq_stats,
        socket_connect_timeout=settings.redis_socket_connect_timeout_seconds,
        socket_timeout=settings.redis_socket_timeout_seconds,
        return_error=True,
    )
    parts = [http_body.rstrip("\n")]
    if celery_metrics:
        parts.append(celery_metrics.rstrip("\n"))
    if scrape_error:
        parts.append("# HELP secaudit_metrics_scrape_errors Celery/Redis scrape failures")
        parts.append("# TYPE secaudit_metrics_scrape_errors gauge")
        parts.append("secaudit_metrics_scrape_errors 1")
        logging.getLogger(__name__).warning("Celery metrics scrape failed: %s", scrape_error)
    else:
        parts.append("# HELP secaudit_metrics_scrape_errors Celery/Redis scrape failures")
        parts.append("# TYPE secaudit_metrics_scrape_errors gauge")
        parts.append("secaudit_metrics_scrape_errors 0")
    return "\n".join(parts) + "\n"


PROMETHEUS_CONTENT_TYPE = CONTENT_TYPE_LATEST
