"""Unit tests for the shared OpenTelemetry bootstrap in ``secaudit_core.tracing``.

The tests rely on OTel's in-memory span exporter so no real Tempo/Jaeger is
required. Each test resets the provider to make the module state deterministic.
"""

from __future__ import annotations

import pytest


@pytest.fixture()
def isolated_tracing(monkeypatch):
    """Reset tracing state and force a fresh TracerProvider per test."""
    from opentelemetry import trace as ot_trace
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    from secaudit_core import tracing as tracing_module

    tracing_module.reset_for_tests()

    exporter = InMemorySpanExporter()
    provider = TracerProvider(resource=Resource.create({"service.name": "test"}))
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    monkeypatch.setattr(ot_trace, "_TRACER_PROVIDER", provider, raising=False)
    ot_trace.set_tracer_provider(provider)

    monkeypatch.setattr(
        tracing_module,
        "_tracing_disabled",
        lambda _settings=None: False,
    )

    yield exporter, tracing_module

    tracing_module.reset_for_tests()


def test_configure_tracing_is_noop_when_disabled(monkeypatch):
    from secaudit_core import tracing as tracing_module
    from secaudit_core.settings import SecAuditSettings

    tracing_module.reset_for_tests()
    settings = SecAuditSettings(otel_enabled=False)

    assert tracing_module.configure_tracing("secaudit-test", settings=settings) is False
    assert tracing_module.is_tracing_enabled(settings) is False


def test_configure_tracing_requires_endpoint():
    from secaudit_core import tracing as tracing_module
    from secaudit_core.settings import SecAuditSettings

    tracing_module.reset_for_tests()
    settings = SecAuditSettings(otel_enabled=True, otel_exporter_otlp_endpoint=None)
    assert tracing_module.configure_tracing("secaudit-test", settings=settings) is False


def test_start_span_records_attributes(isolated_tracing):
    exporter, tracing_module = isolated_tracing

    with tracing_module.start_span(
        "executor.ssh test-script",
        attributes={"secaudit.executor": "ssh", "net.peer.name": "example"},
        kind="client",
    ):
        pass

    spans = exporter.get_finished_spans()
    assert len(spans) == 1
    assert spans[0].name == "executor.ssh test-script"
    assert spans[0].attributes["secaudit.executor"] == "ssh"
    assert spans[0].attributes["net.peer.name"] == "example"


def test_start_span_records_exception(isolated_tracing):
    exporter, tracing_module = isolated_tracing

    with pytest.raises(RuntimeError, match="^boom$") as raised:
        with tracing_module.start_span("executor.oscap.xccdf boom"):
            raise RuntimeError("boom")

    # Must re-raise the original error — never mask it as
    # ``generator didn't stop after throw()`` via a second yield.
    assert "generator didn't stop" not in str(raised.value)

    spans = exporter.get_finished_spans()
    assert spans[0].name == "executor.oscap.xccdf boom"
    assert spans[0].status.status_code.name == "ERROR"
    assert any(event.name == "exception" for event in spans[0].events)


def test_set_current_span_attributes_updates_active_span(isolated_tracing):
    exporter, tracing_module = isolated_tracing

    with tracing_module.start_span("secaudit.job"):
        tracing_module.set_current_span_attributes(
            {"secaudit.job_run_id": 42, "secaudit.connection_mode": "auto"}
        )

    span = exporter.get_finished_spans()[0]
    assert span.attributes["secaudit.job_run_id"] == 42
    assert span.attributes["secaudit.connection_mode"] == "auto"


def test_inject_and_extract_context_roundtrip(isolated_tracing):
    exporter, tracing_module = isolated_tracing

    carrier: dict = {}
    with tracing_module.start_span("parent") as parent_span:
        tracing_module.inject_context(carrier)
        trace_id = tracing_module.current_trace_id_hex()

    assert trace_id is not None
    assert "traceparent" in carrier
    assert trace_id in carrier["traceparent"]

    context = tracing_module.extract_context(carrier)
    assert context is not None


def test_send_task_injects_traceparent(monkeypatch, isolated_tracing):
    exporter, tracing_module = isolated_tracing

    captured: dict = {}

    class DummyResult:
        id = "task-123"

    class DummyCelery:
        def __init__(self, *args, **kwargs):
            pass

        def send_task(self, task_name, args=None, kwargs=None, **options):
            captured["task_name"] = task_name
            captured["args"] = args
            captured["kwargs"] = kwargs
            captured["options"] = options
            return DummyResult()

    from secaudit_core import celery_dispatch as dispatch_module

    dispatch_module._celery_client.cache_clear()
    monkeypatch.setattr(dispatch_module, "create_celery_app", lambda _name, _settings: DummyCelery())

    with tracing_module.start_span("api.request"):
        task_id = dispatch_module.send_task(
            "app.tasks.run_compliance_job",
            [42],
            broker_url="redis://localhost:6379/0",
            queue="compliance",
        )

    assert task_id == "task-123"
    headers = captured["options"].get("headers", {})
    assert "traceparent" in headers
