"""Compare two AuditFlow runs for inventory host drift."""

from __future__ import annotations

from typing import Literal

from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import AuthUser
from app.models import AuditFlowHost, AuditFlowRun
from app.schemas import (
    AuditFlowInventoryDriftHost,
    AuditFlowInventoryDriftReport,
    AuditFlowInventoryDriftSummary,
)
from app.services.audit_flow import load_run
from app.services.object_rbac import assert_can_access

InventoryChange = Literal["appeared", "disappeared", "unchanged", "changed"]


def _host_key(row: AuditFlowHost) -> str:
    fingerprint = (getattr(row, "ssh_host_key_fingerprint", None) or "").strip().lower()
    if fingerprint:
        return f"fp:{fingerprint}"
    return f"ip:{(row.ip_address or '').strip().lower()}"


def _host_row(row: AuditFlowHost, change: InventoryChange) -> AuditFlowInventoryDriftHost:
    return AuditFlowInventoryDriftHost(
        change=change,
        ip_address=row.ip_address,
        hostname=row.hostname,
        ssh_host_key_fingerprint=getattr(row, "ssh_host_key_fingerprint", None),
        os_guess=row.os_guess,
        profile_id=row.profile_id,
        profile_name=row.profile_name,
        left_run_id=None,
        right_run_id=None,
    )


def compare_audit_flow_hosts(
    left_run: AuditFlowRun,
    right_run: AuditFlowRun,
) -> AuditFlowInventoryDriftReport:
    left_map = {_host_key(h): h for h in (left_run.hosts or [])}
    right_map = {_host_key(h): h for h in (right_run.hosts or [])}
    all_keys = set(left_map) | set(right_map)

    items: list[AuditFlowInventoryDriftHost] = []
    counts = {"appeared": 0, "disappeared": 0, "unchanged": 0, "changed": 0}

    for key in sorted(all_keys):
        left = left_map.get(key)
        right = right_map.get(key)
        if left is None and right is not None:
            change: InventoryChange = "appeared"
            row = _host_row(right, change)
            row.right_run_id = right_run.id
        elif right is None and left is not None:
            change = "disappeared"
            row = _host_row(left, change)
            row.left_run_id = left_run.id
        else:
            assert left is not None and right is not None
            left_profile = left.profile_id
            right_profile = right.profile_id
            left_os = (left.os_guess or "").strip().lower()
            right_os = (right.os_guess or "").strip().lower()
            if left_profile != right_profile or left_os != right_os:
                change = "changed"
            else:
                change = "unchanged"
            row = AuditFlowInventoryDriftHost(
                change=change,
                ip_address=right.ip_address or left.ip_address,
                hostname=right.hostname or left.hostname,
                ssh_host_key_fingerprint=(
                    getattr(right, "ssh_host_key_fingerprint", None)
                    or getattr(left, "ssh_host_key_fingerprint", None)
                ),
                os_guess=right.os_guess or left.os_guess,
                profile_id=right.profile_id or left.profile_id,
                profile_name=right.profile_name or left.profile_name,
                left_run_id=left_run.id,
                right_run_id=right_run.id,
                left_os_guess=left.os_guess,
                right_os_guess=right.os_guess,
                left_profile_name=left.profile_name,
                right_profile_name=right.profile_name,
            )
        counts[change] += 1
        items.append(row)

    summary = AuditFlowInventoryDriftSummary(
        left_run_id=left_run.id,
        right_run_id=right_run.id,
        left_hosts=len(left_map),
        right_hosts=len(right_map),
        appeared=counts["appeared"],
        disappeared=counts["disappeared"],
        unchanged=counts["unchanged"],
        changed=counts["changed"],
    )
    return AuditFlowInventoryDriftReport(summary=summary, items=items)


async def fetch_audit_flow_inventory_drift(
    db: AsyncSession,
    user: AuthUser,
    *,
    left_run_id: int,
    right_run_id: int,
) -> AuditFlowInventoryDriftReport:
    if left_run_id == right_run_id:
        raise HTTPException(status_code=400, detail="Cannot compare a run to itself")

    left = await load_run(db, left_run_id)
    if not left:
        raise HTTPException(status_code=404, detail="Left AuditFlow run not found")
    assert_can_access(user, left.owner_sub)

    right = await load_run(db, right_run_id)
    if not right:
        raise HTTPException(status_code=404, detail="Right AuditFlow run not found")
    assert_can_access(user, right.owner_sub)

    return compare_audit_flow_hosts(left, right)
