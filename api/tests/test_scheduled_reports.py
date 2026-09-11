from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from secaudit_core.enums import ScheduledReportDelivery, ScheduledReportFormat
from secaudit_core.models import ScheduledReport
from secaudit_core.scheduled_reports import build_report_attachments, should_trigger_schedule


def test_should_trigger_schedule_when_never_delivered():
    schedule = ScheduledReport(
        id=1,
        name="weekly",
        job_id=1,
        cron_expression="0 2 * * 1",
        is_active=True,
        report_format=ScheduledReportFormat.PDF,
        delivery_type=ScheduledReportDelivery.EMAIL,
    )
    schedule.last_delivered_at = None
    assert should_trigger_schedule(schedule, datetime(2026, 7, 7, 3, 0, tzinfo=UTC)) is True


def test_should_trigger_schedule_skips_when_already_fired():
    schedule = ScheduledReport(
        id=1,
        name="weekly",
        job_id=1,
        cron_expression="0 2 * * 1",
        is_active=True,
        report_format=ScheduledReportFormat.PDF,
        delivery_type=ScheduledReportDelivery.EMAIL,
    )
    schedule.last_delivered_at = datetime(2026, 7, 7, 2, 30, tzinfo=UTC)
    assert should_trigger_schedule(schedule, datetime(2026, 7, 7, 2, 45, tzinfo=UTC)) is False


def test_build_report_attachments_pdf_only(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        "secaudit_core.scheduled_reports.render_run_report_pdf",
        lambda *_args, **_kwargs: b"%PDF-1.4",
    )
    job_run = SimpleNamespace(id=7, check_results=[], job=SimpleNamespace(name="Audit"))
    attachments = build_report_attachments(job_run, None, {}, ScheduledReportFormat.PDF)
    assert len(attachments) == 1
    assert attachments[0][0].endswith(".pdf")


def test_build_report_attachments_both_formats(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        "secaudit_core.scheduled_reports.render_run_report_html",
        lambda *_args, **_kwargs: "<html></html>",
    )
    monkeypatch.setattr(
        "secaudit_core.scheduled_reports.render_run_report_pdf",
        lambda *_args, **_kwargs: b"%PDF-1.4",
    )
    job_run = SimpleNamespace(id=7, check_results=[], job=SimpleNamespace(name="Audit"))
    attachments = build_report_attachments(job_run, None, {}, ScheduledReportFormat.BOTH)
    assert len(attachments) == 2
    names = {item[0] for item in attachments}
    assert any(name.endswith(".html") for name in names)
    assert any(name.endswith(".pdf") for name in names)


def test_scheduled_reports_router_requires_auth():
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as client:
        response = client.get("/api/v1/scheduled-reports")
    assert response.status_code == 401
