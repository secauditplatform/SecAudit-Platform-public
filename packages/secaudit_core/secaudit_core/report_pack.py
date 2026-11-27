"""Run report ZIP packs (HTML + executive PDF + CSV + signed evidence)."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import zipfile
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from secaudit_core.evidence_signing import sign_manifest, signature_b64
from secaudit_core.models import AuditLog, ComplianceWaiver, JobRun
from secaudit_core.reports import (
    fetch_run_report_context_sync,
    render_run_report_html,
    render_run_report_pdf,
)
from secaudit_core.settings import SecAuditSettings
from secaudit_core.waivers import resolve_waived_fail_map_sync

RUN_PACK_SCHEMA = "secaudit.run-pack.v1"
EVIDENCE_PACK_SCHEMA = "secaudit.evidence-pack.v1"


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json_bytes(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")


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
    """Build a downloadable run pack ZIP (HTML + PDF + CSV + manifest)."""
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
            ("evidence/run.json", _json_bytes(evidence_run)),
            ("evidence/waivers.json", _json_bytes(evidence_waivers)),
            ("evidence/profile.json", _json_bytes(evidence_profile)),
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

    key_path = SecAuditSettings().evidence_signing_key_path
    signature = b""
    public_pem = b""
    signed = False
    if include_evidence:
        evidence_meta["signature"] = "ed25519"
        evidence_meta["sig_file"] = "manifest.sig"
        evidence_meta["public_key_file"] = "evidence/signing_public.pem"
        manifest["evidence"] = evidence_meta

    manifest_bytes = _json_bytes(manifest)
    if include_evidence:
        try:
            signature, public_pem = sign_manifest(manifest_bytes, key_path=key_path)
            signed = True
        except Exception:
            signed = False
            evidence_meta.pop("signature", None)
            evidence_meta.pop("sig_file", None)
            evidence_meta.pop("public_key_file", None)
            manifest["evidence"] = evidence_meta
            manifest_bytes = _json_bytes(manifest)

    members.append(("manifest.json", manifest_bytes))
    if include_evidence:
        members.append(("manifest.sha256", (_sha256_hex(manifest_bytes) + "\n").encode("ascii")))
        if signed:
            members.append(("manifest.sig", (signature_b64(signature) + "\n").encode("ascii")))
            members.append(("evidence/signing_public.pem", public_pem))

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in members:
            archive.writestr(name, payload)
        if not include_evidence:
            archive.writestr("evidence/.keep", b"")
    return buffer.getvalue()


def _checks_csv(job_run: JobRun, hosts: dict) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["host_id", "host", "rule_tech_name", "status", "message"])
    for check in sorted(job_run.check_results or [], key=lambda c: (c.host_id, c.rule_tech_name)):
        host = hosts.get(check.host_id)
        label = host.name if host is not None else f"host#{check.host_id}"
        status = check.status.value if hasattr(check.status, "value") else str(check.status)
        writer.writerow([check.host_id, label, check.rule_tech_name, status, check.message or ""])
    return buf.getvalue()


def _evidence_docs_sync(db: Session, job_run: JobRun, hosts: dict) -> tuple[dict, dict, dict]:
    """Minimal evidence docs for packs (no API-only AuditLog initiator walk beyond one query)."""
    initiator = None
    rows = db.execute(
        select(AuditLog.actor_username, AuditLog.metadata_json)
        .where(AuditLog.action == "job.run", AuditLog.resource_id == str(job_run.job_id))
        .order_by(AuditLog.id.desc())
        .limit(200)
    )
    for username, meta in rows.all():
        if isinstance(meta, dict) and meta.get("run_id") == job_run.id:
            initiator = username
            break

    snapshot = job_run.profile_snapshot if isinstance(job_run.profile_snapshot, dict) else {}
    profile_doc = {
        "schema": EVIDENCE_PACK_SCHEMA,
        "profile_id": snapshot.get("profile_id") or (job_run.job.profile_id if job_run.job else None),
        "profile_name": snapshot.get("profile_name") or "",
        "encoding": snapshot.get("encoding") or "",
        "version": snapshot.get("version") or "",
        "version_number": snapshot.get("version_number"),
        "version_label": snapshot.get("version_label") or "",
        "variables": snapshot.get("variables") or [],
    }
    host_rows = [
        {
            "host_id": hid,
            "name": getattr(hosts.get(hid), "name", None),
            "hostname": getattr(hosts.get(hid), "hostname", None),
        }
        for hid in sorted({c.host_id for c in (job_run.check_results or [])})
    ]
    status_counts: dict[str, int] = {}
    for check in job_run.check_results or []:
        key = check.status.value if hasattr(check.status, "value") else str(check.status)
        status_counts[key] = status_counts.get(key, 0) + 1
    run_doc = {
        "schema": EVIDENCE_PACK_SCHEMA,
        "run_id": job_run.id,
        "job_id": job_run.job_id,
        "initiator": initiator,
        "hosts": host_rows,
        "profile": {
            "profile_id": profile_doc["profile_id"],
            "profile_name": profile_doc["profile_name"],
            "encoding": profile_doc["encoding"],
            "version": profile_doc["version"],
            "version_number": profile_doc["version_number"],
            "version_label": profile_doc["version_label"],
        },
        "totals": status_counts,
    }
    profile_id = profile_doc["profile_id"]
    waivers: list = []
    if profile_id is not None:
        waivers = list(
            db.execute(select(ComplianceWaiver).where(ComplianceWaiver.profile_id == profile_id)).scalars()
        )
    waiver_rows = [
        {
            "id": w.id,
            "status": w.status.value if hasattr(w.status, "value") else str(w.status),
            "rule_tech_name": w.rule_tech_name,
            "host_id": w.host_id,
            "job_id": w.job_id,
            "change_ticket": w.change_ticket,
        }
        for w in waivers
    ]
    return run_doc, {"schema": EVIDENCE_PACK_SCHEMA, "run_id": job_run.id, "waivers": waiver_rows}, profile_doc


def materialize_run_pack(db: Session, run_id: int, *, locale: str = "en") -> bytes:
    """Full HTML + executive PDF + CSV + signed evidence pack for a run."""
    context = fetch_run_report_context_sync(db, run_id)
    if context is None:
        raise ValueError("Job run not found")
    job_run, profile, hosts = context
    job = getattr(job_run, "job", None)
    profile_id = job.profile_id if job is not None else getattr(profile, "id", None)
    waived_ids = set(
        resolve_waived_fail_map_sync(
            db,
            list(job_run.check_results or []),
            profile_id=profile_id,
            job_id=job_run.job_id,
        ).keys()
    )
    html = render_run_report_html(
        job_run, profile, hosts, locale=locale, waived_check_ids=waived_ids, executive=False
    )
    pdf = render_run_report_pdf(
        job_run, profile, hosts, locale=locale, waived_check_ids=waived_ids, executive=True
    )
    evidence_run, evidence_waivers, evidence_profile = _evidence_docs_sync(db, job_run, hosts)
    return build_run_package_zip(
        run_id=run_id,
        html=html,
        pdf=pdf,
        csv_text=_checks_csv(job_run, hosts),
        locale=locale,
        include_evidence=True,
        evidence_run=evidence_run,
        evidence_waivers=evidence_waivers,
        evidence_profile=evidence_profile,
    )
