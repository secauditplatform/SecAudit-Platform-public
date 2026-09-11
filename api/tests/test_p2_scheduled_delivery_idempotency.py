"""Scheduled report delivery idempotency (claim-before-deliver)."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from secaudit_core.enums import JobStatus, ScheduledReportDelivery, ScheduledReportFormat
from secaudit_core.scheduled_reports import (
    build_delivery_key,
    deliver_scheduled_report,
)
from secaudit_core.settings import SecAuditSettings


def _schedule(**overrides):
    base = dict(
        id=1,
        name="daily",
        job_id=10,
        cron_expression="0 9 * * *",
        is_active=True,
        report_format=ScheduledReportFormat.PDF,
        delivery_type=ScheduledReportDelivery.EMAIL,
        config_json={"to_addresses": ["a@example.com"], "smtp_host": "smtp.test"},
        encrypted_secret=None,
        last_delivered_at=None,
        last_delivered_run_id=None,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def _job_run(**overrides):
    base = dict(
        id=55,
        job_id=10,
        status=JobStatus.COMPLETED,
        job=SimpleNamespace(name="Job A"),
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_delivery_key_is_stable_for_same_window():
    schedule = _schedule()
    run = _job_run()
    now = datetime(2026, 7, 18, 10, 0, tzinfo=UTC)
    key1 = build_delivery_key(schedule, run, now)
    key2 = build_delivery_key(schedule, run, now)
    assert key1 == key2
    assert "run-55" in key1
    assert key1.startswith("1:")


def test_second_delivery_is_skipped_after_claim(monkeypatch):
    settings = SecAuditSettings(scheduled_reports_enabled=True)
    schedule = _schedule()
    run = _job_run()
    db = MagicMock()

    # First claim succeeds; second claim returns None (already delivered).
    attempts = {"n": 0}

    def fake_claim(_db, _schedule, _run, _key):
        attempts["n"] += 1
        if attempts["n"] == 1:
            return SimpleNamespace(
                status="claimed",
                error_message=None,
                completed_at=None,
            )
        return None

    monkeypatch.setattr(
        "secaudit_core.scheduled_reports._claim_delivery",
        fake_claim,
    )
    monkeypatch.setattr(
        "secaudit_core.scheduled_reports.fetch_run_report_context_sync",
        lambda *_a, **_k: (run, SimpleNamespace(), {}),
    )
    monkeypatch.setattr(
        "secaudit_core.scheduled_reports.build_report_attachments",
        lambda *_a, **_k: [("r.pdf", b"%PDF", "application/pdf")],
    )
    send = MagicMock()
    monkeypatch.setattr("secaudit_core.scheduled_reports._send_report_email", send)

    db.get.return_value = run

    first = deliver_scheduled_report(db, schedule, settings, run_id=55)
    assert first["delivered"] is True
    send.assert_called_once()

    second = deliver_scheduled_report(db, schedule, settings, run_id=55)
    assert second["delivered"] is False
    assert second["reason"] == "already_delivered_or_in_progress"
    assert send.call_count == 1


def test_claim_before_send_prevents_duplicate_on_crash_window(monkeypatch):
    """If claim is committed but send never happens, retry within window is blocked."""
    settings = SecAuditSettings(scheduled_reports_enabled=True)
    schedule = _schedule()
    run = _job_run()
    db = MagicMock()
    db.get.return_value = run

    monkeypatch.setattr(
        "secaudit_core.scheduled_reports._claim_delivery",
        lambda *_a, **_k: None,
    )

    result = deliver_scheduled_report(db, schedule, settings, run_id=55)
    assert result["delivered"] is False
    assert result["reason"] == "already_delivered_or_in_progress"
