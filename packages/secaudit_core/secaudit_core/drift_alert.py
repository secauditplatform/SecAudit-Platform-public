"""Lightweight compliance regression detection for notification emit."""

from __future__ import annotations

from secaudit_core.enums import CheckStatus
from secaudit_core.reports import build_report_summary_dict


def _status_value(status: object) -> str:
    return status.value if hasattr(status, "value") else str(status)


def _is_pass(status: object) -> bool:
    return _status_value(status) == CheckStatus.PASS.value


def _is_fail_or_error(status: object) -> bool:
    return _status_value(status) in (CheckStatus.FAIL.value, CheckStatus.ERROR.value)


def detect_compliance_regression(
    baseline_checks: list,
    current_checks: list,
    *,
    baseline_run_id: int = 0,
    current_run_id: int = 0,
) -> tuple[bool, str]:
    """Return (regressed, detail) when new FAIL/ERROR vs PASS baseline or % dropped."""
    baseline_map = {(c.host_id, c.rule_tech_name): c for c in baseline_checks}
    current_map = {(c.host_id, c.rule_tech_name): c for c in current_checks}
    new_fails = 0
    for key, current in current_map.items():
        baseline = baseline_map.get(key)
        if baseline is None:
            continue
        if _is_pass(baseline.status) and _is_fail_or_error(current.status):
            new_fails += 1

    baseline_summary = build_report_summary_dict(baseline_run_id, baseline_checks)
    current_summary = build_report_summary_dict(current_run_id, current_checks)
    baseline_pct = float(baseline_summary["compliance_percent"])
    current_pct = float(current_summary["compliance_percent"])
    pct_dropped = current_pct < baseline_pct

    if new_fails == 0 and not pct_dropped:
        return False, ""

    parts: list[str] = []
    if new_fails:
        parts.append(f"{new_fails} new FAIL/ERROR vs baseline PASS")
    if pct_dropped:
        parts.append(f"compliance {baseline_pct:.1f}% → {current_pct:.1f}%")
    return True, "; ".join(parts)
