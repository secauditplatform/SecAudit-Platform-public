from datetime import UTC, date, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.core.auth import create_local_token
from app.main import app
from app.models import CheckStatus, UserRole
from app.schemas import ComplianceTimelinePoint, HostCompliancePoint, ProfileCompliancePoint
from app.services.trends import (
    aggregate_checks_by_host,
    aggregate_profile_compliance,
    build_timeline_points,
)


def _check(run_id: int, host_id: int, rule: str, status: CheckStatus) -> SimpleNamespace:
    return SimpleNamespace(job_run_id=run_id, host_id=host_id, rule_tech_name=rule, status=status)


def _run(
    run_id: int,
    job_id: int,
    job_name: str,
    finished_at: datetime,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=run_id,
        job_id=job_id,
        finished_at=finished_at,
        job=SimpleNamespace(name=job_name, profile_id=1),
    )


def test_resolve_period_uses_inclusive_date_range():
    from app.services.trends import resolve_period

    start, end, span = resolve_period(date_from=date(2026, 8, 1), date_to=date(2026, 8, 10))

    assert start.date() == date(2026, 8, 1)
    assert end.date() == date(2026, 8, 10)
    assert span == 10


def test_resolve_period_swaps_inverted_range():
    from app.services.trends import resolve_period

    start, _end, span = resolve_period(date_from=date(2026, 8, 10), date_to=date(2026, 8, 1))

    assert start.date() == date(2026, 8, 1)
    assert span == 10


def test_resolve_period_falls_back_to_days():
    from app.services.trends import resolve_period

    start, end, span = resolve_period(days=7)
    assert span == 7
    assert (end - start) <= timedelta(days=7, hours=1)


def test_build_timeline_points_computes_compliance():
    finished = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)
    runs = [_run(1, 10, "Daily audit", finished)]
    checks_by_run = {
        1: [
            _check(1, 1, "R1", CheckStatus.PASS),
            _check(1, 1, "R2", CheckStatus.PASS),
            _check(1, 2, "R1", CheckStatus.FAIL),
        ]
    }

    points = build_timeline_points(runs, checks_by_run)

    assert len(points) == 1
    assert points[0].run_id == 1
    assert points[0].job_name == "Daily audit"
    assert points[0].compliance_percent == 66.67
    assert points[0].passed == 2
    assert points[0].failed == 1
    assert points[0].total_checks == 3


def test_build_timeline_points_empty_runs():
    assert build_timeline_points([], {}) == []


def test_aggregate_checks_by_host_groups_and_sorts():
    checks = [
        _check(1, 2, "R1", CheckStatus.PASS),
        _check(1, 2, "R2", CheckStatus.FAIL),
        _check(1, 1, "R1", CheckStatus.PASS),
        _check(1, 1, "R2", CheckStatus.PASS),
    ]
    host_names = {1: "web-01", 2: "db-01"}

    points = aggregate_checks_by_host(checks, host_names)

    assert len(points) == 2
    assert points[0].host_id == 1
    assert points[0].host_name == "web-01"
    assert points[0].compliance_percent == 100.0
    assert points[1].host_id == 2
    assert points[1].compliance_percent == 50.0


def test_aggregate_checks_by_host_empty():
    assert aggregate_checks_by_host([], {}) == []


def test_aggregate_profile_compliance_averages_per_profile():
    finished_old = datetime(2026, 1, 10, 10, 0, tzinfo=UTC)
    finished_new = datetime(2026, 1, 20, 10, 0, tzinfo=UTC)
    runs = [
        _run(1, 10, "Job A", finished_old),
        _run(2, 11, "Job B", finished_new),
    ]
    checks_by_run = {
        1: [_check(1, 1, "R1", CheckStatus.PASS), _check(1, 1, "R2", CheckStatus.FAIL)],
        2: [_check(2, 1, "R1", CheckStatus.PASS), _check(2, 1, "R2", CheckStatus.PASS)],
    }
    runs[1].job.profile_id = 1
    profiles = {1: SimpleNamespace(profile_name="Demo Linux")}

    points = aggregate_profile_compliance(runs, checks_by_run, profiles)

    assert len(points) == 1
    assert points[0].profile_name == "Demo Linux"
    assert points[0].job_count == 2
    assert points[0].avg_compliance_percent == 75.0
    assert points[0].latest_run_id == 2


@patch("app.api.v1.routers.reports.fetch_compliance_timeline", new_callable=AsyncMock)
def test_compliance_timeline_endpoint(mock_fetch: AsyncMock, client: TestClient, auth_headers: dict):
    finished = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)
    mock_fetch.return_value = [
        ComplianceTimelinePoint(
            run_id=1,
            job_id=10,
            job_name="Daily audit",
            finished_at=finished,
            compliance_percent=80.0,
            passed=4,
            failed=1,
            total_checks=5,
        )
    ]

    response = client.get("/api/v1/reports/trends/compliance?days=30", headers=auth_headers)

    assert response.status_code == 200
    body = response.json()
    assert len(body) == 1
    assert body[0]["compliance_percent"] == 80.0
    mock_fetch.assert_awaited_once()


@patch("app.api.v1.routers.reports.assert_job_run_access", new_callable=AsyncMock)
@patch("app.api.v1.routers.reports.fetch_compliance_by_host", new_callable=AsyncMock)
def test_compliance_by_host_endpoint(
    mock_fetch: AsyncMock, _mock_assert: AsyncMock, client: TestClient, auth_headers: dict
):
    mock_fetch.return_value = [
        HostCompliancePoint(
            host_id=1,
            host_name="web-01",
            compliance_percent=100.0,
            passed=2,
            failed=0,
            total_checks=2,
        )
    ]

    response = client.get("/api/v1/reports/trends/by-host?run_id=5", headers=auth_headers)

    assert response.status_code == 200
    assert response.json()[0]["host_name"] == "web-01"
    mock_fetch.assert_awaited_once()


@patch("app.api.v1.routers.reports.fetch_compliance_by_profile", new_callable=AsyncMock)
def test_compliance_by_profile_endpoint_empty(mock_fetch: AsyncMock, client: TestClient, auth_headers: dict):
    mock_fetch.return_value = []

    response = client.get("/api/v1/reports/trends/by-profile?days=7", headers=auth_headers)

    assert response.status_code == 200
    assert response.json() == []
    mock_fetch.assert_awaited_once()


@patch("app.api.v1.routers.reports.fetch_compliance_by_profile", new_callable=AsyncMock)
def test_compliance_by_profile_endpoint(mock_fetch: AsyncMock, client: TestClient, auth_headers: dict):
    mock_fetch.return_value = [
        ProfileCompliancePoint(
            profile_id=1,
            profile_name="Demo Linux",
            job_count=2,
            avg_compliance_percent=85.5,
            latest_run_id=9,
        )
    ]

    response = client.get("/api/v1/reports/trends/by-profile", headers=auth_headers)

    assert response.status_code == 200
    assert response.json()[0]["avg_compliance_percent"] == 85.5


def test_build_ops_overview_aggregates_kpis_and_mix():
    from app.models import JobStatus
    from app.services.trends import build_ops_overview

    finished = datetime(2026, 1, 15, 12, 0, tzinfo=UTC)
    overview = build_ops_overview(
        days=30,
        completed_runs=[_run(1, 10, "Daily audit", finished)],
        period_runs=[
            SimpleNamespace(status=JobStatus.COMPLETED),
            SimpleNamespace(status=JobStatus.FAILED),
        ],
        checks=[
            _check(1, 1, "ssh-root", CheckStatus.PASS),
            _check(1, 1, "firewall", CheckStatus.FAIL),
            _check(1, 2, "ssh-root", CheckStatus.FAIL),
        ],
        host_os={1: "linux", 2: "windows"},
        waiver_approved=3,
        waiver_pending=1,
        prev_avg=50.0,
    )

    assert overview.kpis.completed_runs == 1
    assert overview.kpis.failed_runs == 1
    assert overview.kpis.hosts == 2
    assert overview.kpis.passed == 1
    assert overview.kpis.failed == 2
    assert overview.kpis.waivers_approved == 3
    assert overview.kpis.avg_compliance_percent == 33.33
    assert overview.top_failing_rules[0].fail_count == 1
    assert {item.rule_tech_name for item in overview.top_failing_rules} == {"firewall", "ssh-root"}
    assert {item.platform for item in overview.by_platform} == {"linux", "windows"}
    assert overview.daily[0].runs == 1
    assert overview.kpis.jobs == 1
    assert overview.by_job[0].job_name == "Daily audit"
    assert overview.by_job[0].runs == 1
    assert overview.by_job[0].latest_run_id == 1
    assert any(cell.runs for cell in overview.heatmap)
