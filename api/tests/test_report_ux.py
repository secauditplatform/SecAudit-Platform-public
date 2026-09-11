"""Unit/integration-ish tests for CSV export and multi-run compare."""

from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from app.core.auth import create_local_token
from app.main import app
from app.models import CheckStatus, JobStatus, UserRole
from app.schemas import MultiRunCompareReport
from app.services.report_ux import (
    build_multi_run_compare,
    render_check_results_csv,
    render_multi_compare_csv,
)


def _check(
    host_id: int,
    rule: str,
    status: CheckStatus,
    message: str | None = None,
    *,
    check_id: int = 1,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=check_id,
        host_id=host_id,
        rule_tech_name=rule,
        status=status,
        message=message,
        created_at=datetime(2026, 7, 14, 12, 0, tzinfo=UTC),
    )


def _run(run_id: int, job_id: int = 1) -> SimpleNamespace:
    return SimpleNamespace(
        id=run_id,
        job_id=job_id,
        status=JobStatus.COMPLETED,
        finished_at=datetime(2026, 7, 14, 13, 0, tzinfo=UTC),
    )


def test_render_check_results_csv_filters_by_severity_and_status():
    checks = [
        _check(1, "R1", CheckStatus.PASS, "ok", check_id=1),
        _check(1, "R2", CheckStatus.FAIL, "bad", check_id=2),
        _check(2, "R3", CheckStatus.SKIP, "skip", check_id=3),
    ]
    hosts = {
        1: SimpleNamespace(name="web-1"),
        2: SimpleNamespace(name="db-1"),
    }
    severity = {"R1": "low", "R2": "high", "R3": "medium"}

    csv_text = render_check_results_csv(
        run_id=42,
        checks=checks,
        hosts=hosts,
        severity_by_rule=severity,
        status_filter="fail",
        severity_filter="high",
    )

    lines = [line for line in csv_text.strip().split("\n") if line]
    assert lines[0].startswith("run_id,host_id,host_name")
    assert len(lines) == 2
    assert "R2" in lines[1]
    assert "high" in lines[1]
    assert "web-1" in lines[1]


def test_build_multi_run_compare_matrix():
    runs = [_run(10), _run(20), _run(30)]
    checks_by_run = {
        10: [_check(1, "R1", CheckStatus.PASS), _check(1, "R2", CheckStatus.FAIL)],
        20: [_check(1, "R1", CheckStatus.PASS), _check(1, "R2", CheckStatus.PASS)],
        30: [_check(1, "R1", CheckStatus.FAIL)],
    }

    report = build_multi_run_compare(
        job_id=1,
        runs=runs,
        checks_by_run=checks_by_run,
        severity_by_rule={"R1": "medium", "R2": "critical"},
    )

    assert report.run_ids == [10, 20, 30]
    assert len(report.runs) == 3
    assert report.runs[1].compliance_percent == 100.0
    assert len(report.rows) == 2

    r1 = next(row for row in report.rows if row.rule_tech_name == "R1")
    assert r1.severity == "medium"
    assert [cell.status for cell in r1.cells] == [
        CheckStatus.PASS,
        CheckStatus.PASS,
        CheckStatus.FAIL,
    ]

    r2 = next(row for row in report.rows if row.rule_tech_name == "R2")
    assert [cell.status for cell in r2.cells] == [CheckStatus.FAIL, CheckStatus.PASS, None]

    csv_text = render_multi_compare_csv(report)
    assert "run_10_status" in csv_text
    assert "run_30_message" in csv_text
    assert "critical" in csv_text


@pytest.mark.asyncio
async def test_fetch_multi_run_compare_rejects_single_run():
    from app.services.report_ux import fetch_multi_run_compare

    with pytest.raises(Exception) as exc:
        await fetch_multi_run_compare(AsyncMock(), [1])
    assert exc.value.status_code == 400


def test_compare_endpoint_requires_auth(client: TestClient):
    response = client.get("/api/v1/reports/compare?run_ids=1,2")
    assert response.status_code in (401, 403)


def test_csv_endpoint_requires_auth(client: TestClient):
    response = client.get("/api/v1/reports/runs/1/report.csv")
    assert response.status_code in (401, 403)


def test_multi_compare_schema_roundtrip():
    report = MultiRunCompareReport(
        job_id=1,
        run_ids=[1, 2],
        runs=[],
        rows=[],
    )
    assert report.model_dump()["run_ids"] == [1, 2]
