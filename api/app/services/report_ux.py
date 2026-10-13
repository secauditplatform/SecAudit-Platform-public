"""Report CSV export and multi-run comparison helpers."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import zipfile
from collections.abc import Iterable
from datetime import UTC, datetime

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models import AuditLog, CheckResult, CheckStatus, ComplianceWaiver, Host, JobRun, Profile, Rule
from app.schemas import (
    MultiRunCompareCell,
    MultiRunCompareReport,
    MultiRunCompareRow,
    MultiRunCompareRunSummary,
    ReportSummary,
)
from app.services.cve_feed import load_feed_entries, references_for_check
from app.services.reports import build_report_summary
from secaudit_core.sensitive_data import redact_sensitive

RUN_PACK_SCHEMA = "secaudit.run-pack.v1"
EVIDENCE_PACK_SCHEMA = "secaudit.evidence-pack.v1"


def _normalize_severity(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = value.strip().lower()
    return cleaned or None


def _csv_escape_row(values: Iterable[object]) -> list[str]:
    out: list[str] = []
    for value in values:
        if value is None:
            out.append("")
        else:
            out.append(str(value))
    return out


async def _severity_by_tech_name(db: AsyncSession, profile_id: int | None) -> dict[str, str]:
    if profile_id is None:
        return {}
    result = await db.execute(select(Rule).where(Rule.profile_id == profile_id))
    mapping: dict[str, str] = {}
    for rule in result.scalars().all():
        severity = _normalize_severity(rule.severity)
        if severity:
            mapping[rule.tech_name] = severity
    return mapping


def render_check_results_csv(
    *,
    run_id: int,
    checks: list[CheckResult],
    hosts: dict[int, Host],
    severity_by_rule: dict[str, str],
    status_filter: str | None = None,
    severity_filter: str | None = None,
    host_id_filter: int | None = None,
    rule_filter: str | None = None,
    cve_ids_by_check_id: dict[int, list[str]] | None = None,
) -> str:
    status_norm = status_filter.strip().lower() if status_filter else None
    severity_norm = _normalize_severity(severity_filter)
    rule_query = rule_filter.strip().lower() if rule_filter else None

    header = [
        "run_id",
        "host_id",
        "host_name",
        "rule_tech_name",
        "severity",
        "status",
        "message",
        "created_at",
    ]
    if cve_ids_by_check_id is not None:
        header.append("cve_ids")
    rows: list[list[str]] = [header]

    for check in sorted(checks, key=lambda c: (c.host_id, c.rule_tech_name, c.id)):
        status_value = check.status.value if isinstance(check.status, CheckStatus) else str(check.status)
        severity = severity_by_rule.get(check.rule_tech_name)
        if status_norm and status_value.lower() != status_norm:
            continue
        if severity_norm and (severity or "") != severity_norm:
            continue
        if host_id_filter is not None and check.host_id != host_id_filter:
            continue
        if rule_query and rule_query not in check.rule_tech_name.lower():
            continue

        host = hosts.get(check.host_id)
        values: list[object] = [
            run_id,
            check.host_id,
            host.name if host else "",
            check.rule_tech_name,
            severity or "",
            status_value,
            check.message or "",
            check.created_at.isoformat() if check.created_at else "",
        ]
        if cve_ids_by_check_id is not None:
            # Advisory column only. The status cell stays the check result.
            ids = cve_ids_by_check_id.get(check.id, []) if status_value.lower() == "fail" else []
            values.append(" ".join(ids))
        rows.append(_csv_escape_row(values))

    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerows(rows)
    return buffer.getvalue()


def render_multi_compare_csv(report: MultiRunCompareReport) -> str:
    header = ["host_id", "rule_tech_name", "severity"]
    for run_id in report.run_ids:
        header.append(f"run_{run_id}_status")
        header.append(f"run_{run_id}_message")

    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(header)

    for row in report.rows:
        cells_by_run = {cell.run_id: cell for cell in row.cells}
        values: list[object] = [row.host_id, row.rule_tech_name, row.severity or ""]
        for run_id in report.run_ids:
            cell = cells_by_run.get(run_id)
            status = ""
            message = ""
            if cell and cell.status is not None:
                status = cell.status.value if isinstance(cell.status, CheckStatus) else str(cell.status)
                message = cell.message or ""
            values.extend([status, message])
        writer.writerow(_csv_escape_row(values))

    return buffer.getvalue()


async def fetch_run_csv(
    db: AsyncSession,
    run_id: int,
    *,
    status: str | None = None,
    severity: str | None = None,
    host_id: int | None = None,
    rule: str | None = None,
) -> tuple[str, str]:
    result = await db.execute(
        select(JobRun)
        .options(selectinload(JobRun.check_results), selectinload(JobRun.job))
        .where(JobRun.id == run_id)
    )
    job_run = result.scalar_one_or_none()
    if not job_run:
        raise HTTPException(status_code=404, detail="Job run not found")

    host_ids = {c.host_id for c in job_run.check_results}
    hosts: dict[int, Host] = {}
    if host_ids:
        hosts_result = await db.execute(select(Host).where(Host.id.in_(host_ids)))
        hosts = {h.id: h for h in hosts_result.scalars().all()}

    profile_id = job_run.job.profile_id if job_run.job else None
    severity_by_rule = await _severity_by_tech_name(db, profile_id)
    feed_entries = await load_feed_entries(db)
    cve_ids_by_check_id: dict[int, list[str]] | None = None
    if feed_entries:
        profile_name = None
        if profile_id is not None:
            profile = await db.get(Profile, profile_id)
            profile_name = profile.profile_name if profile is not None else None
        cve_ids_by_check_id = {}
        for check in job_run.check_results:
            status_value = check.status.value if isinstance(check.status, CheckStatus) else str(check.status)
            refs = references_for_check(
                feed_entries,
                status=status_value,
                rule_tech_name=check.rule_tech_name,
                profile_name=profile_name,
            )
            cve_ids_by_check_id[check.id] = [ref.cve_id for ref in refs]
    content = render_check_results_csv(
        run_id=run_id,
        checks=list(job_run.check_results),
        hosts=hosts,
        severity_by_rule=severity_by_rule,
        status_filter=status,
        severity_filter=severity,
        host_id_filter=host_id,
        rule_filter=rule,
        cve_ids_by_check_id=cve_ids_by_check_id,
    )
    filename = f"report-{run_id}.csv"
    return content, filename


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.isoformat().replace("+00:00", "Z")


def _json_bytes(payload: dict) -> bytes:
    return (json.dumps(payload, indent=2, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")


def _evidence_bytes(payload: dict) -> bytes:
    raw = _json_bytes(payload).decode("utf-8")
    cleaned = redact_sensitive(raw)
    text = cleaned if isinstance(cleaned, str) else raw
    return text.encode("utf-8")


def _status_value(status: object) -> str:
    return status.value if hasattr(status, "value") else str(status)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


def waivers_affecting_run(
    waivers: Iterable,
    checks: Iterable,
    *,
    profile_id: int | None,
    job_id: int | None,
    at: datetime | None,
) -> list:
    """Waivers that covered a FAIL on this run at the time the run finished."""
    from secaudit_core.enums import CheckStatus, WaiverStatus
    from secaudit_core.waivers import waiver_matches_check

    if profile_id is None or at is None:
        return []
    moment = _as_utc(at)
    chosen: dict[int, object] = {}
    for check in checks:
        if _status_value(check.status) != CheckStatus.FAIL.value:
            continue
        candidates = []
        for waiver in waivers:
            status = _status_value(waiver.status)
            if status not in {WaiverStatus.APPROVED.value, WaiverStatus.EXPIRED.value}:
                continue
            approved = waiver.approved_at or waiver.created_at
            if approved is not None and _as_utc(approved) > moment:
                continue
            if waiver.expires_at is not None and _as_utc(waiver.expires_at) <= moment:
                continue
            if not waiver_matches_check(
                waiver,
                profile_id=profile_id,
                rule_tech_name=check.rule_tech_name,
                host_id=check.host_id,
                job_id=job_id,
            ):
                continue
            candidates.append(waiver)
        if not candidates:
            continue
        best = sorted(
            candidates,
            key=lambda waiver: (
                1 if waiver.host_id is not None else 0,
                1 if waiver.job_id is not None else 0,
                waiver.id,
            ),
            reverse=True,
        )[0]
        chosen[best.id] = best
    return [chosen[key] for key in sorted(chosen)]


def build_evidence_documents(
    *,
    job_run,
    hosts: dict[int, Host],
    waivers: Iterable,
    initiator: str | None,
) -> tuple[dict, dict, dict]:
    """Machine-readable run, waiver, and profile documents for the evidence pack.

    Profile identity comes from the snapshot taken when the run started. The live
    profile row is not substituted when that snapshot is missing.
    """
    from secaudit_core.sensitive_data import redact_sensitive

    checks = list(job_run.check_results or [])
    totals = {"PASS": 0, "FAIL": 0, "ERROR": 0, "SKIP": 0}
    for check in checks:
        key = _status_value(check.status).upper()
        if key in totals:
            totals[key] += 1

    host_rows = [
        {"id": host_id, "name": hosts[host_id].name if host_id in hosts else None}
        for host_id in sorted({check.host_id for check in checks})
    ]
    snapshot = job_run.profile_snapshot if isinstance(job_run.profile_snapshot, dict) else None
    profile_doc = {
        "schema": EVIDENCE_PACK_SCHEMA,
        "run_id": job_run.id,
        "captured_at_start": snapshot is not None,
        "profile_id": snapshot.get("profile_id") if snapshot else None,
        "profile_name": snapshot.get("profile_name") if snapshot else None,
        "version": snapshot.get("version") if snapshot else None,
        "encoding": snapshot.get("encoding") if snapshot else None,
    }
    job = job_run.job
    profile_id = snapshot.get("profile_id") if snapshot else (job.profile_id if job else None)
    moment = job_run.finished_at or job_run.started_at
    affecting = waivers_affecting_run(
        waivers,
        checks,
        profile_id=profile_id,
        job_id=job_run.job_id,
        at=moment,
    )
    waiver_rows = []
    for waiver in affecting:
        reason = redact_sensitive(waiver.reason or "")
        waiver_rows.append(
            {
                "id": waiver.id,
                "status": _status_value(waiver.status),
                "expires_at": _iso(waiver.expires_at),
                "reason": reason if isinstance(reason, str) else str(reason),
                "change_ticket": waiver.change_ticket,
                "approved_by": waiver.approved_by,
                "rule_tech_name": waiver.rule_tech_name,
                "host_id": waiver.host_id,
                "job_id": waiver.job_id,
            }
        )
    run_doc = {
        "schema": EVIDENCE_PACK_SCHEMA,
        "run_id": job_run.id,
        "job_id": job_run.job_id,
        "created_at": _iso(job_run.created_at),
        "started_at": _iso(job_run.started_at),
        "finished_at": _iso(job_run.finished_at),
        "initiator": initiator,
        "mode": "check_mode" if job_run.check_mode else "live",
        "hosts": host_rows,
        "profile": {
            "profile_id": profile_doc["profile_id"],
            "profile_name": profile_doc["profile_name"],
            "encoding": profile_doc["encoding"],
            "version": profile_doc["version"],
        },
        "totals": totals,
    }
    waivers_doc = {"schema": EVIDENCE_PACK_SCHEMA, "run_id": job_run.id, "waivers": waiver_rows}
    return run_doc, waivers_doc, profile_doc


async def load_run_evidence(db: AsyncSession, job_run: JobRun, hosts: dict[int, Host]) -> tuple[dict, dict, dict]:
    initiator = None
    rows = await db.execute(
        select(AuditLog.actor_username, AuditLog.metadata_json)
        .where(AuditLog.action == "job.run", AuditLog.resource_id == str(job_run.job_id))
        .order_by(AuditLog.id.desc())
        .limit(200)
    )
    for username, meta in rows.all():
        if isinstance(meta, dict) and meta.get("run_id") == job_run.id:
            initiator = username
            break

    profile_id = None
    if isinstance(job_run.profile_snapshot, dict):
        profile_id = job_run.profile_snapshot.get("profile_id")
    elif job_run.job is not None:
        profile_id = job_run.job.profile_id
    waivers: list[ComplianceWaiver] = []
    if profile_id is not None:
        result = await db.execute(
            select(ComplianceWaiver).where(ComplianceWaiver.profile_id == profile_id)
        )
        waivers = list(result.scalars().all())
    return build_evidence_documents(
        job_run=job_run,
        hosts=hosts,
        waivers=waivers,
        initiator=initiator,
    )


def build_run_package_zip(
    *,
    run_id: int,
    html: str | bytes,
    pdf: bytes,
    csv_text: str,
    locale: str,
    generated_at: datetime | None = None,
    include_evidence: bool = False,
    evidence_run: dict | None = None,
    evidence_waivers: dict | None = None,
    evidence_profile: dict | None = None,
) -> bytes:
    """Build a downloadable run pack ZIP (HTML + PDF + CSV + manifest).

    When ``include_evidence`` is set, the archive also contains
    ``evidence/run.json``, ``evidence/waivers.json`` and ``evidence/profile.json``.
    ``manifest.sha256`` is the sha256 of ``manifest.json`` and is not listed inside
    the manifest, so the hash is not part of the bytes it covers.
    """
    html_bytes = html.encode("utf-8") if isinstance(html, str) else html
    csv_bytes = csv_text.encode("utf-8")
    stamped = generated_at or datetime.now(UTC)
    if stamped.tzinfo is None:
        stamped = stamped.replace(tzinfo=UTC)

    members: list[tuple[str, bytes]] = [
        (f"report-{run_id}.html", html_bytes),
        (f"report-{run_id}.pdf", pdf),
        (f"report-{run_id}.csv", csv_bytes),
    ]

    evidence_meta: dict[str, object] = {
        "included": False,
        "schema": EVIDENCE_PACK_SCHEMA,
    }
    if include_evidence:
        if evidence_run is None or evidence_waivers is None or evidence_profile is None:
            raise ValueError("evidence documents are required when include_evidence is set")
        evidence_members = [
            ("evidence/run.json", _evidence_bytes(evidence_run)),
            ("evidence/waivers.json", _evidence_bytes(evidence_waivers)),
            ("evidence/profile.json", _evidence_bytes(evidence_profile)),
        ]
        members.extend(evidence_members)
        evidence_meta = {
            "included": True,
            "schema": EVIDENCE_PACK_SCHEMA,
            "manifest_sha256_file": "manifest.sha256",
        }

    manifest: dict[str, object] = {
        "schema": RUN_PACK_SCHEMA,
        "run_id": run_id,
        "generated_at": stamped.isoformat().replace("+00:00", "Z"),
        "locale": locale,
        "files": [
            {"name": name, "sha256": _sha256_hex(payload), "size": len(payload)}
            for name, payload in members
        ],
        "evidence": evidence_meta,
    }

    manifest_bytes = _json_bytes(manifest)
    members.append(("manifest.json", manifest_bytes))
    if include_evidence:
        members.append(("manifest.sha256", (_sha256_hex(manifest_bytes) + "\n").encode("ascii")))

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in members:
            archive.writestr(name, payload)
        if not include_evidence:
            archive.writestr("evidence/.keep", b"")
    return buffer.getvalue()


def build_multi_run_compare(
    *,
    job_id: int,
    runs: list[JobRun],
    checks_by_run: dict[int, list[CheckResult]],
    severity_by_rule: dict[str, str],
) -> MultiRunCompareReport:
    ordered_ids = [run.id for run in runs]
    run_summaries: list[MultiRunCompareRunSummary] = []
    for run in runs:
        summary: ReportSummary = build_report_summary(run.id, checks_by_run.get(run.id, []))
        run_summaries.append(
            MultiRunCompareRunSummary(
                run_id=run.id,
                job_id=run.job_id,
                status=run.status,
                finished_at=run.finished_at,
                compliance_percent=summary.compliance_percent,
                total_checks=summary.total_checks,
                passed=summary.passed,
                failed=summary.failed,
                skipped=summary.skipped,
                errors=summary.errors,
            )
        )

    all_keys: set[tuple[int, str]] = set()
    maps: dict[int, dict[tuple[int, str], CheckResult]] = {}
    for run_id, checks in checks_by_run.items():
        mapping = {(c.host_id, c.rule_tech_name): c for c in checks}
        maps[run_id] = mapping
        all_keys.update(mapping.keys())

    rows: list[MultiRunCompareRow] = []
    for host_id, rule_tech_name in sorted(all_keys):
        cells: list[MultiRunCompareCell] = []
        for run_id in ordered_ids:
            check = maps.get(run_id, {}).get((host_id, rule_tech_name))
            cells.append(
                MultiRunCompareCell(
                    run_id=run_id,
                    status=check.status if check else None,
                    message=(check.message if check and check.message else None),
                )
            )
        rows.append(
            MultiRunCompareRow(
                host_id=host_id,
                rule_tech_name=rule_tech_name,
                severity=severity_by_rule.get(rule_tech_name),
                cells=cells,
            )
        )

    return MultiRunCompareReport(
        job_id=job_id,
        run_ids=ordered_ids,
        runs=run_summaries,
        rows=rows,
    )


async def fetch_multi_run_compare(db: AsyncSession, run_ids: list[int]) -> MultiRunCompareReport:
    unique_ids = list(dict.fromkeys(run_ids))
    if len(unique_ids) < 2:
        raise HTTPException(status_code=400, detail="Select at least two distinct runs to compare")
    if len(unique_ids) > 8:
        raise HTTPException(status_code=400, detail="Compare supports at most 8 runs")

    result = await db.execute(
        select(JobRun).options(selectinload(JobRun.job)).where(JobRun.id.in_(unique_ids))
    )
    found = {run.id: run for run in result.scalars().all()}
    missing = [run_id for run_id in unique_ids if run_id not in found]
    if missing:
        raise HTTPException(status_code=404, detail=f"Job run(s) not found: {missing}")

    runs = [found[run_id] for run_id in unique_ids]
    job_ids = {run.job_id for run in runs}
    if len(job_ids) != 1:
        raise HTTPException(status_code=400, detail="Compared runs must belong to the same job")

    job_id = runs[0].job_id
    checks_by_run: dict[int, list[CheckResult]] = {}
    for run in runs:
        checks_result = await db.execute(select(CheckResult).where(CheckResult.job_run_id == run.id))
        checks_by_run[run.id] = list(checks_result.scalars().all())

    profile_id = runs[0].job.profile_id if runs[0].job else None
    severity_by_rule = await _severity_by_tech_name(db, profile_id)
    return build_multi_run_compare(
        job_id=job_id,
        runs=runs,
        checks_by_run=checks_by_run,
        severity_by_rule=severity_by_rule,
    )


__all__ = [
    "EVIDENCE_PACK_SCHEMA",
    "RUN_PACK_SCHEMA",
    "build_evidence_documents",
    "build_run_package_zip",
    "fetch_multi_run_compare",
    "fetch_run_csv",
    "load_run_evidence",
    "render_check_results_csv",
    "render_multi_compare_csv",
]
