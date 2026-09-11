"""OpenTelemetry bootstrap shared by API and workers.

Instrumentation is opt-in via `OTEL_ENABLED=true` and an OTLP endpoint
(`OTEL_EXPORTER_OTLP_ENDPOINT`). When disabled, all helpers become no-ops so
the platform runs unchanged in environments without an OTLP collector.
"""

from __future__ import annotations

import logging
import os
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from typing import Any

from secaudit_core.settings import SecAuditSettings

_configure_lock = threading.Lock()
_configured_services: set[str] = set()
_logger = logging.getLogger("secaudit.tracing")


def _parse_headers(value: str | None) -> dict[str, str]:
    result: dict[str, str] = {}
    if not value:
        return result
    for pair in value.split(","):
        if "=" not in pair:
            continue
        key, val = pair.split("=", 1)
        key = key.strip()
        val = val.strip()
        if key:
            result[key] = val
    return result


def _parse_resource_attributes(value: str | None) -> dict[str, str]:
    return _parse_headers(value)


def _tracing_disabled(settings: SecAuditSettings | None) -> bool:
    if settings is None:
        settings = SecAuditSettings()
    if not settings.otel_enabled:
        return True
    return not settings.otel_exporter_otlp_endpoint


def is_tracing_enabled(settings: SecAuditSettings | None = None) -> bool:
    """True when OTLP export is configured for this process."""
    return not _tracing_disabled(settings)


def configure_tracing(
    service_name: str,
    *,
    settings: SecAuditSettings | None = None,
    extra_resource_attributes: Mapping[str, str] | None = None,
) -> bool:
    """Configure a global TracerProvider + OTLP exporter for the current process.

    Returns True if tracing became active (or was already active); False when
    disabled by settings. The call is idempotent per (service_name) — invoking
    it multiple times is safe.
    """
    if settings is None:
        settings = SecAuditSettings()

    if _tracing_disabled(settings):
        _logger.debug("Tracing disabled for service %s", service_name)
        return False

    resolved_name = settings.otel_service_name or service_name

    with _configure_lock:
        if resolved_name in _configured_services:
            return True

        try:
            from opentelemetry import trace
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import (
                BatchSpanProcessor,
                ConsoleSpanExporter,
                SimpleSpanProcessor,
            )
            from opentelemetry.sdk.trace.sampling import (
                ALWAYS_ON,
                ParentBasedTraceIdRatio,
            )
        except Exception as exc:  # pragma: no cover — deps missing in edge envs
            _logger.warning("OpenTelemetry SDK not installed: %s", exc)
            return False

        attributes: dict[str, Any] = {
            "service.name": resolved_name,
            "service.namespace": settings.otel_service_namespace,
            "service.version": settings.app_version,
            "deployment.environment": settings.app_env,
        }
        attributes.update(_parse_resource_attributes(settings.otel_resource_attributes))
        if extra_resource_attributes:
            attributes.update(dict(extra_resource_attributes))

        try:
            ratio = float(settings.otel_sampler_ratio)
        except (TypeError, ValueError):
            ratio = 1.0
        sampler = ALWAYS_ON if ratio >= 1.0 else ParentBasedTraceIdRatio(max(ratio, 0.0))

        endpoint = settings.otel_exporter_otlp_endpoint or ""
        trace_endpoint = endpoint.rstrip("/")
        if trace_endpoint and not trace_endpoint.endswith("/v1/traces"):
            trace_endpoint = f"{trace_endpoint}/v1/traces"

        headers = _parse_headers(settings.otel_exporter_otlp_headers)
        # Profile OTEL env fallbacks so libraries respect the same config.
        os.environ.setdefault("OTEL_SERVICE_NAME", resolved_name)
        os.environ.setdefault("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint)

        try:
            exporter = OTLPSpanExporter(endpoint=trace_endpoint or None, headers=headers or None)
        except Exception as exc:  # pragma: no cover — collector unreachable
            _logger.warning("Failed to create OTLP exporter: %s", exc)
            return False

        provider = TracerProvider(resource=Resource.create(attributes), sampler=sampler)
        provider.add_span_processor(BatchSpanProcessor(exporter))
        if settings.otel_console_export:
            provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))

        trace.set_tracer_provider(provider)
        _configured_services.add(resolved_name)
        _logger.info(
            "OpenTelemetry configured for service=%s endpoint=%s sampler_ratio=%s",
            resolved_name,
            trace_endpoint or endpoint,
            ratio,
        )

    _apply_common_instrumentations(settings)
    return True


def _apply_common_instrumentations(settings: SecAuditSettings) -> None:
    if not settings.otel_instrument_logging:
        return
    try:
        from opentelemetry.instrumentation.logging import LoggingInstrumentor

        LoggingInstrumentor().instrument(set_logging_format=False)
    except Exception as exc:  # pragma: no cover
        _logger.debug("LoggingInstrumentor skipped: %s", exc)


def instrument_fastapi(app, *, settings: SecAuditSettings | None = None) -> None:
    """Attach FastAPI middleware for HTTP server spans."""
    if _tracing_disabled(settings):
        return
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        FastAPIInstrumentor.instrument_app(app)
    except Exception as exc:  # pragma: no cover
        _logger.warning("FastAPIInstrumentor failed: %s", exc)


def instrument_sqlalchemy(engine=None, *, settings: SecAuditSettings | None = None) -> None:
    """Instrument SQLAlchemy synchronously or via a specific engine."""
    if _tracing_disabled(settings):
        return
    try:
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

        kwargs: dict[str, Any] = {}
        if engine is not None:
            sync_engine = getattr(engine, "sync_engine", engine)
            kwargs["engine"] = sync_engine
        SQLAlchemyInstrumentor().instrument(**kwargs)
    except Exception as exc:  # pragma: no cover
        _logger.warning("SQLAlchemyInstrumentor failed: %s", exc)


def instrument_asyncpg(*, settings: SecAuditSettings | None = None) -> None:
    if _tracing_disabled(settings):
        return
    try:
        from opentelemetry.instrumentation.asyncpg import AsyncPGInstrumentor

        AsyncPGInstrumentor().instrument()
    except Exception as exc:  # pragma: no cover
        _logger.debug("AsyncPGInstrumentor skipped: %s", exc)


def instrument_http_clients(*, settings: SecAuditSettings | None = None) -> None:
    if _tracing_disabled(settings):
        return
    try:
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
        from opentelemetry.instrumentation.requests import RequestsInstrumentor

        HTTPXClientInstrumentor().instrument()
        RequestsInstrumentor().instrument()
    except Exception as exc:  # pragma: no cover
        _logger.debug("HTTP client instrumentation skipped: %s", exc)


def instrument_celery(*, settings: SecAuditSettings | None = None) -> None:
    if _tracing_disabled(settings):
        return
    try:
        from opentelemetry.instrumentation.celery import CeleryInstrumentor

        CeleryInstrumentor().instrument()
    except Exception as exc:  # pragma: no cover
        _logger.warning("CeleryInstrumentor failed: %s", exc)


def inject_context(carrier: dict | None = None) -> dict:
    """Serialize the active trace context (W3C traceparent) into `carrier`."""
    payload: dict = carrier if carrier is not None else {}
    if _tracing_disabled(None):
        return payload
    try:
        from opentelemetry.propagate import inject

        inject(payload)
    except Exception as exc:  # pragma: no cover
        _logger.debug("Trace context injection failed: %s", exc)
    return payload


def extract_context(carrier: Mapping[str, str] | None):
    """Extract an OTel context from a mapping (e.g. Celery task headers)."""
    if _tracing_disabled(None) or not carrier:
        return None
    try:
        from opentelemetry.propagate import extract

        return extract(dict(carrier))
    except Exception as exc:  # pragma: no cover
        _logger.debug("Trace context extraction failed: %s", exc)
        return None


@contextmanager
def start_span(
    name: str,
    *,
    attributes: Mapping[str, Any] | None = None,
    kind: str = "internal",
) -> Iterator[Any]:
    """Context manager that opens a span if tracing is active, else yields None.

    Setup failures (imports / provider) fall back to a no-op span. Exceptions
    raised *inside* the yielded body are recorded on the span and re-raised;
    they must not be caught by a second ``yield`` (that produces
    ``RuntimeError: generator didn't stop after throw()``).
    """
    if _tracing_disabled(None):
        yield None
        return

    try:
        from opentelemetry import trace
        from opentelemetry.trace import SpanKind

        tracer = trace.get_tracer("secaudit")
        span_kind = {
            "server": SpanKind.SERVER,
            "client": SpanKind.CLIENT,
            "producer": SpanKind.PRODUCER,
            "consumer": SpanKind.CONSUMER,
            "internal": SpanKind.INTERNAL,
        }.get(kind, SpanKind.INTERNAL)
    except Exception as exc:  # pragma: no cover
        _logger.debug("start_span fallback: %s", exc)
        yield None
        return

    with tracer.start_as_current_span(name, kind=span_kind) as span:
        if attributes:
            for key, value in attributes.items():
                if value is None:
                    continue
                try:
                    span.set_attribute(key, value)
                except Exception:
                    span.set_attribute(key, str(value))
        try:
            yield span
        except Exception as exc:
            try:
                span.record_exception(exc)
                from opentelemetry.trace import Status, StatusCode

                span.set_status(Status(StatusCode.ERROR, str(exc)))
            except Exception:
                pass
            raise


def current_trace_id_hex() -> str | None:
    """Return the current trace id as 32-hex string, or None if none is active."""
    if _tracing_disabled(None):
        return None
    try:
        from opentelemetry import trace

        span = trace.get_current_span()
        context = span.get_span_context() if span else None
        if not context or context.trace_id == 0:
            return None
        return f"{context.trace_id:032x}"
    except Exception:  # pragma: no cover
        return None


def set_current_span_attributes(attributes: Mapping[str, Any]) -> None:
    """Attach attributes to the currently active span, when one exists."""
    if _tracing_disabled(None):
        return
    try:
        from opentelemetry import trace

        span = trace.get_current_span()
        if not span:
            return
        for key, value in attributes.items():
            if value is None:
                continue
            try:
                span.set_attribute(key, value)
            except Exception:
                span.set_attribute(key, str(value))
    except Exception:  # pragma: no cover
        pass


def reset_for_tests() -> None:
    """Clear cached configuration so tests can reinitialise cleanly."""
    with _configure_lock:
        _configured_services.clear()
