from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

from app.core.auth import create_local_token
from app.main import app
from app.models import CheckStatus, UserRole
from app.schemas import DiffReport, DiffSummary, DriftReport, DriftSummary
from app.services.drift import (
    classify_drift_change,
    compare_check_results,
    drift_report_to_diff,
)


def _check(host_id: int, rule: str, status: CheckStatus, message: str | None = None) -> SimpleNamespace:
    return SimpleNamespace(host_id=host_id, rule_tech_name=rule, status=status, message=message)


def test_classify_drift_change_improved():
    assert classify_drift_change(CheckStatus.FAIL, CheckStatus.PASS) == "improved"
    assert classify_drift_change(CheckStatus.ERROR, CheckStatus.PASS) == "improved"


def test_classify_drift_change_regressed():
    assert classify_drift_change(CheckStatus.PASS, CheckStatus.FAIL) == "regressed"
    assert classify_drift_change(CheckStatus.PASS, CheckStatus.ERROR) == "regressed"


def test_classify_drift_change_unchanged_same_status():
    assert classify_drift_change(CheckStatus.PASS, CheckStatus.PASS) == "unchanged"
    assert classify_drift_change(CheckStatus.FAIL, CheckStatus.ERROR) == "unchanged"


def test_classify_drift_change_new_and_removed():
    assert classify_drift_change(None, CheckStatus.PASS) == "new"
    assert classify_drift_change(CheckStatus.FAIL, None) == "removed"


def test_compare_check_results_counts_and_compliance_delta():
    baseline = [
        _check(1, "R1", CheckStatus.PASS, "ok"),
        _check(1, "R2", CheckStatus.FAIL, "was fail"),
        _check(2, "R1", CheckStatus.ERROR, "err"),
    ]
    current = [
        _check(1, "R1", CheckStatus.PASS, "still ok"),
        _check(1, "R2", CheckStatus.PASS, "fixed"),
        _check(2, "R3", CheckStatus.FAIL, "new fail"),
    ]

    report = compare_check_results(20, 10, baseline, current)

    assert report.summary.improved == 1
    assert report.summary.regressed == 0
    assert report.summary.unchanged == 1
    assert report.summary.new == 1
    assert report.summary.removed == 1
    assert report.summary.baseline_compliance_percent == 33.33
    assert report.summary.current_compliance_percent == 66.67
    assert report.summary.compliance_delta == 33.34

    improved = [item for item in report.items if item.change == "improved"]
    assert len(improved) == 1
    assert improved[0].rule_tech_name == "R2"
    assert improved[0].baseline_message == "was fail"
    assert improved[0].current_message == "fixed"


def test_drift_report_to_diff_pairs_left_right():
    baseline = [
        _check(1, "R1", CheckStatus.PASS, "left msg"),
        _check(1, "R2", CheckStatus.FAIL, "fail left"),
    ]
    current = [
        _check(1, "R1", CheckStatus.PASS, "right msg"),
        _check(1, "R2", CheckStatus.PASS, "pass right"),
        _check(2, "R3", CheckStatus.SKIP, "only right"),
    ]

    drift = compare_check_results(20, 10, baseline, current)
    diff = drift_report_to_diff(drift)

    assert diff.summary.left_run_id == 10
    assert diff.summary.right_run_id == 20
    assert diff.summary.improved == 1
    assert diff.summary.new == 1
    assert diff.summary.compliance_delta == drift.summary.compliance_delta

    by_key = {row.key: row for row in diff.items}
    assert by_key["1:R1"].left_status == CheckStatus.PASS
    assert by_key["1:R1"].right_status == CheckStatus.PASS
    assert by_key["1:R1"].left_message == "left msg"
    assert by_key["1:R1"].right_message == "right msg"
    assert by_key["1:R1"].change == "unchanged"

    assert by_key["1:R2"].left_status == CheckStatus.FAIL
    assert by_key["1:R2"].right_status == CheckStatus.PASS
    assert by_key["1:R2"].change == "improved"

    assert by_key["2:R3"].left_status is None
    assert by_key["2:R3"].right_status == CheckStatus.SKIP
    assert by_key["2:R3"].change == "new"


@patch("app.api.v1.routers.reports.assert_job_run_access", new_callable=AsyncMock)
@patch("app.api.v1.routers.reports.fetch_drift_report", new_callable=AsyncMock)
def test_drift_endpoint_returns_200(
    mock_fetch: AsyncMock, _mock_assert: AsyncMock, client: TestClient, auth_headers: dict
):
    mock_fetch.return_value = DriftReport(
        summary=DriftSummary(
            current_run_id=2,
            baseline_run_id=1,
            improved=1,
            regressed=0,
            unchanged=2,
            new=0,
            removed=0,
            baseline_compliance_percent=50.0,
            current_compliance_percent=75.0,
            compliance_delta=25.0,
        ),
        items=[],
    )

    response = client.get("/api/v1/reports/runs/2/drift?baseline_run_id=1", headers=auth_headers)

    assert response.status_code == 200
    assert response.json()["summary"]["compliance_delta"] == 25.0
    mock_fetch.assert_awaited_once()


@patch("app.api.v1.routers.reports.assert_job_run_access", new_callable=AsyncMock)
@patch("app.api.v1.routers.reports.fetch_drift_report", new_callable=AsyncMock)
def test_drift_endpoint_returns_404_for_different_jobs(
    mock_fetch: AsyncMock, _mock_assert: AsyncMock, client: TestClient, auth_headers: dict
):
    from fastapi import HTTPException

    mock_fetch.side_effect = HTTPException(status_code=404, detail="Runs belong to different jobs")

    response = client.get("/api/v1/reports/runs/2/drift?baseline_run_id=9", headers=auth_headers)

    assert response.status_code == 404
    assert response.json()["detail"] == "Runs belong to different jobs"


@patch("app.api.v1.routers.reports.assert_job_run_access", new_callable=AsyncMock)
@patch("app.api.v1.routers.reports.fetch_diff_report", new_callable=AsyncMock)
def test_diff_endpoint_returns_200(
    mock_fetch: AsyncMock, _mock_assert: AsyncMock, client: TestClient, auth_headers: dict
):
    mock_fetch.return_value = DiffReport(
        summary=DiffSummary(
            left_run_id=1,
            right_run_id=2,
            improved=1,
            regressed=0,
            unchanged=1,
            new=0,
            removed=0,
            left_compliance_percent=50.0,
            right_compliance_percent=75.0,
            compliance_delta=25.0,
        ),
        items=[],
    )

    response = client.get(
        "/api/v1/reports/diff?left_run_id=1&right_run_id=2",
        headers=auth_headers,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["summary"]["left_run_id"] == 1
    assert body["summary"]["right_run_id"] == 2
    assert body["summary"]["compliance_delta"] == 25.0
    mock_fetch.assert_awaited_once()
    assert mock_fetch.await_args.args[1:] == (1, 2)


@patch("app.api.v1.routers.reports.fetch_diff_report", new_callable=AsyncMock)
def test_diff_endpoint_requires_auth(mock_fetch: AsyncMock, client: TestClient):
    response = client.get("/api/v1/reports/diff?left_run_id=1&right_run_id=2")
    assert response.status_code in (401, 403)
    mock_fetch.assert_not_awaited()


@patch("app.api.v1.routers.reports.assert_job_run_access", new_callable=AsyncMock)
@patch("app.api.v1.routers.reports.assert_job_access", new_callable=AsyncMock)
@patch("app.api.v1.routers.reports.set_job_baseline", new_callable=AsyncMock)
def test_set_job_baseline(
    mock_set: AsyncMock, _mock_job: AsyncMock, _mock_run: AsyncMock, client: TestClient, operator_headers: dict
):
    mock_set.return_value = 5

    response = client.put(
        "/api/v1/reports/jobs/1/baseline",
        headers=operator_headers,
        json={"run_id": 5},
    )

    assert response.status_code == 200
    assert response.json() == {"baseline_run_id": 5}
    mock_set.assert_awaited_once()


@patch("app.api.v1.routers.reports.assert_job_access", new_callable=AsyncMock)
@patch("app.api.v1.routers.reports.get_job_baseline_run_id", new_callable=AsyncMock)
def test_get_job_baseline(
    mock_get: AsyncMock, _mock_job: AsyncMock, client: TestClient, auth_headers: dict
):
    mock_get.return_value = 7

    response = client.get("/api/v1/reports/jobs/1/baseline", headers=auth_headers)

    assert response.status_code == 200
    assert response.json() == {"baseline_run_id": 7}


@patch("app.api.v1.routers.reports.assert_job_access", new_callable=AsyncMock)
@patch("app.api.v1.routers.reports.clear_job_baseline", new_callable=AsyncMock)
def test_clear_job_baseline(
    mock_clear: AsyncMock, _mock_job: AsyncMock, client: TestClient, operator_headers: dict
):
    response = client.delete("/api/v1/reports/jobs/1/baseline", headers=operator_headers)

    assert response.status_code == 204
    mock_clear.assert_awaited_once()
