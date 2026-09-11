"""Compliance waiver matching, scoring, and expiry."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

from secaudit_core.enums import CheckStatus, WaiverStatus
from secaudit_core.reports import build_report_summary_dict
from secaudit_core.waivers import expire_due_waivers, find_matching_waiver


def _waiver(**kwargs):
    defaults = dict(
        id=1,
        profile_id=10,
        rule_tech_name="R1",
        host_id=None,
        job_id=None,
        status=WaiverStatus.APPROVED,
        is_active=True,
        expires_at=None,
    )
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def _check(check_id: int, host_id: int, rule: str, status: CheckStatus):
    return SimpleNamespace(id=check_id, host_id=host_id, rule_tech_name=rule, status=status)


def test_find_matching_waiver_prefers_more_specific_scope():
    global_waiver = _waiver(id=1, host_id=None, job_id=None)
    host_waiver = _waiver(id=2, host_id=5, job_id=None)
    match = find_matching_waiver(
        [global_waiver, host_waiver],
        profile_id=10,
        rule_tech_name="R1",
        host_id=5,
        job_id=3,
    )
    assert match is not None
    assert match.id == 2


def test_find_matching_waiver_ignores_expired():
    expired = _waiver(expires_at=datetime.now(UTC) - timedelta(hours=1))
    match = find_matching_waiver(
        [expired],
        profile_id=10,
        rule_tech_name="R1",
        host_id=1,
        job_id=None,
    )
    assert match is None


def test_build_report_summary_counts_waived_toward_compliance():
    checks = [
        _check(1, 1, "R1", CheckStatus.PASS),
        _check(2, 1, "R2", CheckStatus.FAIL),
        _check(3, 1, "R3", CheckStatus.FAIL),
    ]
    summary = build_report_summary_dict(7, checks, waived_check_ids={2})
    assert summary["passed"] == 1
    assert summary["failed"] == 2
    assert summary["waived"] == 1
    assert summary["compliance_percent_raw"] == 33.33
    assert summary["compliance_percent"] == 66.67


def test_expire_due_waivers_marks_expired():
    class _Scalars:
        def all(self):
            return [waiver]

    class _Result:
        def scalars(self):
            return _Scalars()

    class _Db:
        def execute(self, _stmt):
            return _Result()

    waiver = _waiver(
        id=9,
        status=WaiverStatus.APPROVED,
        is_active=True,
        expires_at=datetime.now(UTC) - timedelta(minutes=1),
    )
    expired_ids = expire_due_waivers(_Db())
    assert expired_ids == [9]
    assert waiver.status == WaiverStatus.EXPIRED
    assert waiver.is_active is False
