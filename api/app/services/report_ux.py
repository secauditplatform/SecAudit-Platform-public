"""Report CSV export and multi-run comparison helpers."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import zipfile
from collections import defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime
from html import escape as xml_escape
from urllib.parse import quote

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
from app.services.reports import build_report_summary, resolve_run_waived_map, waived_check_ids_for_runs
from secaudit_core.report_pack import (
    EVIDENCE_PACK_SCHEMA,
    RUN_PACK_SCHEMA,
    build_run_package_zip,
)
from secaudit_core.sensitive_data import redact_sensitive
from secaudit_core.waivers import host_scope_view, waiver_matches_check


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


def _check_matches_filters(
    check: CheckResult,
    severity_by_rule: dict[str, str],
    *,
    status_norm: str | None,
    severity_norm: str | None,
    host_id_filter: int | None,
    rule_query: str | None,
) -> bool:
    status_value = check.status.value if isinstance(check.status, CheckStatus) else str(check.status)
    severity = severity_by_rule.get(check.rule_tech_name)
    if status_norm and status_value.lower() != status_norm:
        return False
    if severity_norm and (severity or "") != severity_norm:
        return False
    if host_id_filter is not None and check.host_id != host_id_filter:
        return False
    if rule_query and rule_query not in check.rule_tech_name.lower():
        return False
    return True


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
    waived_by_check_id: dict[int, object] | None = None,
) -> str:
    status_norm = status_filter.strip().lower() if status_filter else None
    severity_norm = _normalize_severity(severity_filter)
    rule_query = rule_filter.strip().lower() if rule_filter else None
    waived_map = waived_by_check_id or {}
    visible = [
        check
        for check in checks
        if _check_matches_filters(
            check,
            severity_by_rule,
            status_norm=status_norm,
            severity_norm=severity_norm,
            host_id_filter=host_id_filter,
            rule_query=rule_query,
        )
    ]

    header = [
        "run_id",
        "host_id",
        "host_name",
        "rule_tech_name",
        "severity",
        "status",
        "message",
        "created_at",
        "is_waived",
        "waiver_id",
    ]
    if cve_ids_by_check_id is not None:
        header.append("cve_ids")
    rows: list[list[str]] = [header]

    for check in sorted(visible, key=lambda c: (c.host_id, c.rule_tech_name, c.id)):
        status_value = check.status.value if isinstance(check.status, CheckStatus) else str(check.status)
        severity = severity_by_rule.get(check.rule_tech_name)
        host = hosts.get(check.host_id)
        waiver = waived_map.get(check.id)
        values: list[object] = [
            run_id,
            check.host_id,
            host.name if host else "",
            check.rule_tech_name,
            severity or "",
            status_value,
            check.message or "",
            check.created_at.isoformat() if check.created_at else "",
            "true" if waiver is not None else "false",
            getattr(waiver, "id", "") if waiver is not None else "",
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


def _visible_checks(
    checks: list[CheckResult],
    severity_by_rule: dict[str, str],
    *,
    status_filter: str | None,
    severity_filter: str | None,
    host_id_filter: int | None,
    rule_filter: str | None,
) -> list[CheckResult]:
    status_norm = status_filter.strip().lower() if status_filter else None
    severity_norm = _normalize_severity(severity_filter)
    rule_query = rule_filter.strip().lower() if rule_filter else None
    return [
        check
        for check in checks
        if _check_matches_filters(
            check,
            severity_by_rule,
            status_norm=status_norm,
            severity_norm=severity_norm,
            host_id_filter=host_id_filter,
            rule_query=rule_query,
        )
    ]


def _sarif_level(severity: str | None, status: str) -> str:
    if status == "error" or (severity or "").lower() in {"critical", "crit", "high"}:
        return "error"
    if (severity or "").lower() in {"medium", "med", "warning"}:
        return "warning"
    return "note"


def render_run_sarif(
    *,
    run_id: int,
    checks: list[CheckResult],
    hosts: dict[int, Host],
    severity_by_rule: dict[str, str],
    waived_by_check_id: dict[int, object] | None = None,
    profile_name: str = "",
    tool_version: str = "2.0.0",
    status_filter: str | None = None,
    severity_filter: str | None = None,
    host_id_filter: int | None = None,
    rule_filter: str | None = None,
) -> str:
    waived_map = waived_by_check_id or {}
    visible = _visible_checks(
        checks,
        severity_by_rule,
        status_filter=status_filter,
        severity_filter=severity_filter,
        host_id_filter=host_id_filter,
        rule_filter=rule_filter,
    )
    rules: dict[str, dict] = {}
    results: list[dict] = []
    for check in sorted(visible, key=lambda c: (c.host_id, c.rule_tech_name, c.id)):
        status_value = _status_value(check.status).lower()
        if status_value not in {"fail", "error"}:
            continue
        severity = severity_by_rule.get(check.rule_tech_name) or ""
        host = hosts.get(check.host_id)
        host_label = ""
        if host is not None:
            host_label = (host.hostname or host.name or "").strip()
        if not host_label:
            host_label = str(check.host_id)
        rule_id = check.rule_tech_name
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": rule_id},
                "defaultConfiguration": {"level": _sarif_level(severity, status_value)},
                "properties": {"severity": severity},
            }
        result: dict = {
            "ruleId": rule_id,
            "level": _sarif_level(severity, status_value),
            "message": {"text": check.message or status_value},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f"host://{quote(host_label, safe='')}"},
                    }
                }
            ],
            "properties": {
                "host": host.name if host is not None else host_label,
                "hostname": host.hostname if host is not None else host_label,
                "status": status_value,
                "severity": severity,
            },
        }
        waiver = waived_map.get(check.id)
        if waiver is not None:
            result["suppressions"] = [
                {
                    "kind": "external",
                    "status": "accepted",
                    "justification": getattr(waiver, "reason", "") or "",
                }
            ]
        results.append(result)
    document = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SecAudit",
                        "version": tool_version,
                        "informationUri": "https://github.com/secauditplatform/SecAudit-Platform",
                        "rules": [rules[key] for key in sorted(rules)],
                    }
                },
                "results": results,
                "properties": {"job_run_id": run_id, "profile": profile_name},
            }
        ],
    }
    return json.dumps(document, ensure_ascii=False, indent=2) + "\n"


def _xlsx_col(index: int) -> str:
    name = ""
    while index:
        index, rem = divmod(index - 1, 26)
        name = chr(65 + rem) + name
    return name


def _xlsx_text(value: object) -> str:
    text = "" if value is None else str(value)
    cleaned = "".join(ch for ch in text if ch in "\t\n\r" or ord(ch) >= 32)
    return xml_escape(cleaned, quote=False)


def _xlsx_sheet(rows: list[list[object]]) -> str:
    body: list[str] = []
    for row_index, row in enumerate(rows, start=1):
        cells = []
        for col_index, value in enumerate(row, start=1):
            text = _xlsx_text(value)
            ref = f"{_xlsx_col(col_index)}{row_index}"
            cells.append(f'<c r="{ref}" t="inlineStr"><is><t xml:space="preserve">{text}</t></is></c>')
        body.append(f'<row r="{row_index}">{"".join(cells)}</row>')
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f"<sheetData>{''.join(body)}</sheetData></worksheet>"
    )


def _xlsx_bytes(sheets: list[tuple[str, list[list[object]]]]) -> bytes:
    content_types = [
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">',
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>',
        '<Default Extension="xml" ContentType="application/xml"/>',
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>',
    ]
    workbook_sheets = []
    rels = [
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>',
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">',
    ]
    for index, (name, _rows) in enumerate(sheets, start=1):
        content_types.append(
            f'<Override PartName="/xl/worksheets/sheet{index}.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        )
        workbook_sheets.append(f'<sheet name="{xml_escape(name, quote=True)}" sheetId="{index}" r:id="rId{index}"/>')
        rels.append(
            f'<Relationship Id="rId{index}" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
            f'Target="worksheets/sheet{index}.xml"/>'
        )
    content_types.append("</Types>")
    rels.append("</Relationships>")
    workbook = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f"<sheets>{''.join(workbook_sheets)}</sheets></workbook>"
    )
    root_rels = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        "</Relationships>"
    )
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "".join(content_types))
        archive.writestr("_rels/.rels", root_rels)
        archive.writestr("xl/workbook.xml", workbook)
        archive.writestr("xl/_rels/workbook.xml.rels", "".join(rels))
        for index, (_name, rows) in enumerate(sheets, start=1):
            archive.writestr(f"xl/worksheets/sheet{index}.xml", _xlsx_sheet(rows))
    return buffer.getvalue()


def _host_compliance(passed: int, failed: int, errors: int, waived: int) -> str:
    applicable = passed + failed + errors
    if not applicable:
        return "0"
    return f"{((passed + waived) / applicable) * 100:.2f}"


def render_run_xlsx(
    *,
    run_id: int,
    job_name: str,
    profile_name: str,
    started_at: datetime | None,
    finished_at: datetime | None,
    checks: list[CheckResult],
    hosts: dict[int, Host],
    severity_by_rule: dict[str, str],
    waived_by_check_id: dict[int, object] | None = None,
    waivers: list[ComplianceWaiver] | None = None,
    job_id: int | None = None,
    status_filter: str | None = None,
    severity_filter: str | None = None,
    host_id_filter: int | None = None,
    rule_filter: str | None = None,
) -> bytes:
    waived_map = waived_by_check_id or {}
    visible = _visible_checks(
        checks,
        severity_by_rule,
        status_filter=status_filter,
        severity_filter=severity_filter,
        host_id_filter=host_id_filter,
        rule_filter=rule_filter,
    )
    summary = build_report_summary(
        run_id,
        visible,
        waived_check_ids={check.id for check in visible if check.id in waived_map},
    )
    summary_rows: list[list[object]] = [
        ["Metric", "Value"],
        ["Run", run_id],
        ["Job", job_name],
        ["Profile", profile_name],
        ["Started", _iso(started_at) or ""],
        ["Finished", _iso(finished_at) or ""],
        ["Pass", summary.passed],
        ["Fail", summary.failed],
        ["Error", summary.errors],
        ["Skip", summary.skipped],
        ["Waived", summary.waived],
        ["Total", summary.total_checks],
        ["Compliance %", summary.compliance_percent],
    ]
    by_host: dict[int, dict[str, int]] = defaultdict(lambda: {"pass": 0, "fail": 0, "error": 0, "skip": 0, "waived": 0})
    failed_rows: list[list[object]] = [["Host", "Hostname", "Rule", "Severity", "Status", "Message", "Waived", "Waiver id"]]
    for check in sorted(visible, key=lambda c: (c.host_id, c.rule_tech_name, c.id)):
        status_value = _status_value(check.status).lower()
        bucket = by_host[check.host_id]
        if status_value in bucket:
            bucket[status_value] += 1
        waiver = waived_map.get(check.id)
        if waiver is not None and status_value == "fail":
            bucket["waived"] += 1
        if status_value not in {"fail", "error"}:
            continue
        host = hosts.get(check.host_id)
        failed_rows.append(
            [
                host.name if host is not None else check.host_id,
                host.hostname if host is not None else "",
                check.rule_tech_name,
                severity_by_rule.get(check.rule_tech_name) or "",
                status_value,
                check.message or "",
                "true" if waiver is not None else "false",
                getattr(waiver, "id", "") if waiver is not None else "",
            ]
        )
    host_rows: list[list[object]] = [["Host", "Hostname", "Pass", "Fail", "Error", "Skip", "Waived", "Compliance %"]]
    for host_id, counts in sorted(by_host.items(), key=lambda item: (hosts.get(item[0]).name if hosts.get(item[0]) else "", item[0])):
        host = hosts.get(host_id)
        host_rows.append(
            [
                host.name if host is not None else host_id,
                host.hostname if host is not None else "",
                counts["pass"],
                counts["fail"],
                counts["error"],
                counts["skip"],
                counts["waived"],
                _host_compliance(counts["pass"], counts["fail"], counts["error"], counts["waived"]),
            ]
        )
    waiver_rows: list[list[object]] = [
        ["Id", "Rule", "Host", "Site", "Environment", "Tag", "Reason", "Ticket", "Status", "Expires"]
    ]
    seen: set[int] = set()
    visible_hosts = {check.host_id for check in visible}
    for waiver in waivers or []:
        if waiver.id in seen:
            continue
        if job_id is not None and waiver.job_id is not None and waiver.job_id != job_id:
            continue
        if waiver.host_id is not None and waiver.host_id not in visible_hosts:
            continue
        seen.add(waiver.id)
        host = hosts.get(waiver.host_id) if waiver.host_id is not None else None
        status_value = _status_value(waiver.status)
        waiver_rows.append(
            [
                waiver.id,
                waiver.rule_tech_name,
                host.name if host is not None else (waiver.host_id or ""),
                waiver.scope_site or "",
                waiver.scope_environment or "",
                waiver.scope_tag or "",
                waiver.reason,
                waiver.change_ticket or "",
                status_value,
                _iso(waiver.expires_at) or "",
            ]
        )
    return _xlsx_bytes(
        [
            ("Summary", summary_rows),
            ("By Host", host_rows),
            ("Failed Rules", failed_rows),
            ("Waivers", waiver_rows),
        ]
    )


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
    waived_by_check_id = await resolve_run_waived_map(
        db,
        checks=list(job_run.check_results),
        profile_id=profile_id,
        job_id=job_run.job_id,
    )
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
        waived_by_check_id=waived_by_check_id,
    )
    filename = f"report-{run_id}.csv"
    return content, filename


async def _load_run_for_export(db: AsyncSession, run_id: int):
    result = await db.execute(
        select(JobRun)
        .options(selectinload(JobRun.check_results), selectinload(JobRun.job))
        .where(JobRun.id == run_id)
    )
    job_run = result.scalar_one_or_none()
    if not job_run:
        raise HTTPException(status_code=404, detail="Job run not found")
    host_ids = {check.host_id for check in job_run.check_results}
    hosts: dict[int, Host] = {}
    if host_ids:
        hosts_result = await db.execute(select(Host).where(Host.id.in_(host_ids)))
        hosts = {host.id: host for host in hosts_result.scalars().all()}
    profile_id = job_run.job.profile_id if job_run.job else None
    profile_name = ""
    waivers: list[ComplianceWaiver] = []
    if profile_id is not None:
        profile = await db.get(Profile, profile_id)
        profile_name = profile.profile_name if profile is not None else ""
        waiver_rows = await db.execute(
            select(ComplianceWaiver).where(ComplianceWaiver.profile_id == profile_id)
        )
        waivers = list(waiver_rows.scalars().all())
    severity_by_rule = await _severity_by_tech_name(db, profile_id)
    waived_by_check_id = await resolve_run_waived_map(
        db,
        checks=list(job_run.check_results),
        profile_id=profile_id,
        job_id=job_run.job_id,
    )
    return job_run, hosts, severity_by_rule, waived_by_check_id, profile_name, waivers


async def fetch_run_sarif(
    db: AsyncSession,
    run_id: int,
    *,
    tool_version: str,
    status: str | None = None,
    severity: str | None = None,
    host_id: int | None = None,
    rule: str | None = None,
) -> tuple[str, str]:
    job_run, hosts, severity_by_rule, waived_by_check_id, profile_name, _waivers = await _load_run_for_export(
        db, run_id
    )
    content = render_run_sarif(
        run_id=run_id,
        checks=list(job_run.check_results),
        hosts=hosts,
        severity_by_rule=severity_by_rule,
        waived_by_check_id=waived_by_check_id,
        profile_name=profile_name,
        tool_version=tool_version,
        status_filter=status,
        severity_filter=severity,
        host_id_filter=host_id,
        rule_filter=rule,
    )
    return content, f"report-{run_id}.sarif"


async def fetch_run_xlsx(
    db: AsyncSession,
    run_id: int,
    *,
    status: str | None = None,
    severity: str | None = None,
    host_id: int | None = None,
    rule: str | None = None,
) -> tuple[bytes, str]:
    job_run, hosts, severity_by_rule, waived_by_check_id, profile_name, waivers = await _load_run_for_export(
        db, run_id
    )
    content = render_run_xlsx(
        run_id=run_id,
        job_name=job_run.job.name if job_run.job else "",
        profile_name=profile_name,
        started_at=job_run.started_at,
        finished_at=job_run.finished_at,
        checks=list(job_run.check_results),
        hosts=hosts,
        severity_by_rule=severity_by_rule,
        waived_by_check_id=waived_by_check_id,
        waivers=waivers,
        job_id=job_run.job_id,
        status_filter=status,
        severity_filter=severity,
        host_id_filter=host_id,
        rule_filter=rule,
    )
    return content, f"report-{run_id}.xlsx"


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
    hosts: dict | None = None,
) -> list:
    """Waivers that covered a FAIL on this run at the time the run finished."""
    from secaudit_core.enums import CheckStatus, WaiverStatus
    from secaudit_core.waivers import host_scope_view, waiver_matches_check

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
            host = hosts.get(check.host_id) if hosts else None
            host_site, host_environment, host_tags = host_scope_view(host) if host is not None else (None, None, set())
            if not waiver_matches_check(
                waiver,
                profile_id=profile_id,
                rule_tech_name=check.rule_tech_name,
                host_id=check.host_id,
                job_id=job_id,
                host_site=host_site,
                host_environment=host_environment,
                host_tags=host_tags,
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
                1 if waiver.scope_tag else 0,
                1 if waiver.scope_site else 0,
                1 if waiver.scope_environment else 0,
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
    totals = {"PASS": 0, "FAIL": 0, "ERROR": 0, "SKIP": 0, "WAIVED": 0}
    for check in checks:
        key = _status_value(check.status).upper()
        if key in totals:
            totals[key] += 1

    planned_ids = {
        int(host_id)
        for host_id in (job_run.host_ids or [])
        if host_id is not None
    } or {check.host_id for check in checks}
    host_rows = [
        {"id": host_id, "name": hosts[host_id].name if host_id in hosts else None}
        for host_id in sorted(planned_ids)
    ]
    snapshot = job_run.profile_snapshot if isinstance(job_run.profile_snapshot, dict) else None
    excluded_by_version = []
    if snapshot and isinstance(snapshot.get("excluded_by_version"), list):
        excluded_by_version = [
            {
                "rule_tech_name": str(item.get("rule_tech_name") or ""),
                "version_label": item.get("version_label"),
            }
            for item in snapshot["excluded_by_version"]
            if isinstance(item, dict) and item.get("rule_tech_name")
        ]
    profile_doc = {
        "schema": EVIDENCE_PACK_SCHEMA,
        "run_id": job_run.id,
        "captured_at_start": snapshot is not None,
        "profile_id": snapshot.get("profile_id") if snapshot else None,
        "profile_name": snapshot.get("profile_name") if snapshot else None,
        "version": snapshot.get("version") if snapshot else None,
        "version_number": snapshot.get("version_number") if snapshot else None,
        "version_label": snapshot.get("version_label") if snapshot else None,
        "encoding": snapshot.get("encoding") if snapshot else None,
        "excluded_by_version": excluded_by_version,
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
        hosts=hosts,
    )
    if profile_id is not None:
        totals["WAIVED"] = sum(
            1
            for check in checks
            if _status_value(check.status) == CheckStatus.FAIL.value
            and any(
                waiver_matches_check(
                    waiver,
                    profile_id=profile_id,
                    rule_tech_name=check.rule_tech_name,
                    host_id=check.host_id,
                    job_id=job_run.job_id,
                    host_site=host_scope_view(hosts.get(check.host_id))[0] if hosts.get(check.host_id) else None,
                    host_environment=host_scope_view(hosts.get(check.host_id))[1] if hosts.get(check.host_id) else None,
                    host_tags=host_scope_view(hosts.get(check.host_id))[2] if hosts.get(check.host_id) else None,
                )
                for waiver in affecting
            )
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
        "is_partial": bool(getattr(job_run, "is_partial", False)),
        "subset_kind": getattr(job_run, "subset_kind", None),
        "source_run_id": getattr(job_run, "source_run_id", None),
        "hosts": host_rows,
        "profile": {
            "profile_id": profile_doc["profile_id"],
            "profile_name": profile_doc["profile_name"],
            "encoding": profile_doc["encoding"],
            "version": profile_doc["version"],
            "version_number": profile_doc["version_number"],
            "version_label": profile_doc["version_label"],
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


def build_multi_run_compare(
    *,
    job_id: int,
    runs: list[JobRun],
    checks_by_run: dict[int, list[CheckResult]],
    severity_by_rule: dict[str, str],
    waived_by_run: dict[int, set[int]] | None = None,
) -> MultiRunCompareReport:
    ordered_ids = [run.id for run in runs]
    waived_lookup = waived_by_run or {}
    run_summaries: list[MultiRunCompareRunSummary] = []
    for run in runs:
        summary: ReportSummary = build_report_summary(
            run.id,
            checks_by_run.get(run.id, []),
            waived_check_ids=waived_lookup.get(run.id),
        )
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
    waived_by_run = await waived_check_ids_for_runs(db, runs, checks_by_run)
    return build_multi_run_compare(
        job_id=job_id,
        runs=runs,
        checks_by_run=checks_by_run,
        severity_by_rule=severity_by_rule,
        waived_by_run=waived_by_run,
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
