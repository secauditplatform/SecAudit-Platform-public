"""Evaluate weekly maintenance windows for remediation gates."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo


def _parse_hhmm(value: str) -> tuple[int, int]:
    parts = (value or "00:00").strip().split(":")
    hour = int(parts[0]) if parts and parts[0].isdigit() else 0
    minute = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
    return max(0, min(23, hour)), max(0, min(59, minute))


def _days(raw: str) -> set[int]:
    out: set[int] = set()
    for part in (raw or "").split(","):
        part = part.strip()
        if part.isdigit():
            day = int(part)
            if 0 <= day <= 6:
                out.add(day)
    return out


def window_allows_now(window: Any, *, now: datetime | None = None) -> bool:
    """True when `now` falls inside the weekly local window."""
    if not getattr(window, "enabled", True):
        return True
    tz_name = getattr(window, "tz", None) or "UTC"
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        tz = ZoneInfo("UTC")
    moment = (now or datetime.now(tz)).astimezone(tz)
    # Python weekday: Mon=0 .. Sun=6 — matches our storage.
    if moment.weekday() not in _days(getattr(window, "days_of_week", "0,1,2,3,4")):
        return False
    start_h, start_m = _parse_hhmm(getattr(window, "start_time", "00:00"))
    end_h, end_m = _parse_hhmm(getattr(window, "end_time", "23:59"))
    minutes = moment.hour * 60 + moment.minute
    start = start_h * 60 + start_m
    end = end_h * 60 + end_m
    if start <= end:
        return start <= minutes <= end
    # Overnight window, e.g. 22:00–06:00
    return minutes >= start or minutes <= end


def matching_windows(windows: list[Any], *, site: str | None, environment: str | None) -> list[Any]:
    """Windows that apply to this host (null site/env = wildcard)."""
    site_key = (site or "").strip().lower() or None
    env_key = (environment or "").strip().lower() or None
    matched: list[Any] = []
    for window in windows:
        if not getattr(window, "enabled", True):
            continue
        win_site = (getattr(window, "site", None) or "").strip().lower() or None
        win_env = (getattr(window, "environment", None) or "").strip().lower() or None
        if win_site and win_site != site_key:
            continue
        if win_env and win_env != env_key:
            continue
        matched.append(window)
    return matched


def remediation_blocked_by_windows(
    windows: list[Any],
    hosts: list[Any],
    *,
    now: datetime | None = None,
) -> str | None:
    """
    If any enabled window matches a host and `now` is outside it → block message.
    No matching windows → allow (open calendar).
    """
    for host in hosts:
        site = getattr(host, "site", None)
        environment = getattr(host, "environment", None)
        applicable = matching_windows(windows, site=site, environment=environment)
        if not applicable:
            continue
        if any(window_allows_now(window, now=now) for window in applicable):
            continue
        name = getattr(host, "name", None) or getattr(host, "hostname", None) or "host"
        return f"Remediation blocked: outside maintenance window for {name}"
    return None
