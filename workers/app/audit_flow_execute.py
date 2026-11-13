"""Auto-execute AuditFlow runs after scan reaches READY (scheduled templates)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from sqlalchemy import create_engine, func, or_, select
from sqlalchemy.orm import Session, selectinload, sessionmaker

from secaudit_core.audit_flow_present import job_run_ids_for_host
from secaudit_core.enums import AuditFlowStatus, JobScope, JobStatus, PlaybookKind, ScriptKind
from secaudit_core.models import (
    AuditFlowCredential,
    AuditFlowHost,
    AuditFlowRun,
    CheckScript,
    Credential,
    Host,
    Job,
    JobHost,
    JobRun,
    Playbook,
)
from secaudit_core.script_selection import select_active_scripts
from secaudit_core.task_outbox import enqueue_outbox_row

logger = logging.getLogger(__name__)

_AF_EPHEMERAL_DESCRIPTIONS = frozenset({"AuditFlow ephemeral", "AuditFlow inventory"})


def _log(run_id: int, message: str, *, level: str = "info") -> None:
    try:
        from app.logging_pub import publish_audit_flow_log

        publish_audit_flow_log(run_id, message)
    except Exception:
        getattr(logger, level if level in {"info", "warning", "error"} else "info")(
            "audit_flow %s: %s", run_id, message
        )


def _is_durable_catalog_credential(cred: Credential | None) -> bool:
    if cred is None:
        return False
    if getattr(cred, "is_ephemeral", None) is not False:
        return False
    return (getattr(cred, "description", None) or "") not in _AF_EPHEMERAL_DESCRIPTIONS


def _find_inventory_host(
    db: Session,
    owner_sub: str | None,
    ip: str | None,
    hostname: str | None,
    fingerprint: str | None,
) -> Host | None:
    if owner_sub is None:
        owner_match = Host.owner_sub.is_(None)
    else:
        owner_match = or_(Host.owner_sub == owner_sub, Host.owner_sub.is_(None))

    if fingerprint:
        fp_candidates = list(
            db.execute(
                select(Host)
                .where(
                    Host.ssh_host_key_fingerprint == fingerprint,
                    owner_match,
                    Host.is_ephemeral.is_(False),
                )
                .limit(20)
            )
            .scalars()
            .all()
        )
        if fp_candidates:
            same_owner = [host for host in fp_candidates if host.owner_sub == owner_sub]
            return same_owner[0] if same_owner else fp_candidates[0]

    keys = [value.strip().lower() for value in (ip, hostname) if value and value.strip()]
    if not keys:
        return None
    identity = or_(func.lower(Host.hostname).in_(keys), func.lower(Host.name).in_(keys))
    candidates = list(
        db.execute(select(Host).where(identity, owner_match, Host.is_ephemeral.is_(False)).limit(20))
        .scalars()
        .all()
    )
    if not candidates:
        return None
    same_owner = [host for host in candidates if host.owner_sub == owner_sub]
    return same_owner[0] if same_owner else candidates[0]


def _make_ephemeral_credential(
    db: Session,
    run: AuditFlowRun,
    row: AuditFlowHost,
    flow_cred: AuditFlowCredential,
) -> Credential:
    name = f"af-{run.id}-{row.id}-{flow_cred.id}"[:128]
    existing = db.execute(select(Credential).where(Credential.name == name)).scalar_one_or_none()
    if existing:
        existing.is_ephemeral = True
        existing.description = existing.description or "AuditFlow ephemeral"
        existing.encrypted_secret = flow_cred.encrypted_secret
        existing.encrypted_key_passphrase = flow_cred.encrypted_key_passphrase
        existing.service_username = flow_cred.service_username
        existing.encrypted_service_secret = flow_cred.encrypted_service_secret
        existing.username = flow_cred.username
        existing.credential_type = flow_cred.credential_type
        existing.owner_sub = run.owner_sub
        row.ephemeral_credential_id = existing.id
        return existing
    cred = Credential(
        name=name,
        credential_type=flow_cred.credential_type,
        username=flow_cred.username,
        encrypted_secret=flow_cred.encrypted_secret,
        encrypted_key_passphrase=flow_cred.encrypted_key_passphrase,
        service_username=flow_cred.service_username,
        encrypted_service_secret=flow_cred.encrypted_service_secret,
        description="AuditFlow ephemeral",
        is_ephemeral=True,
        owner_sub=run.owner_sub,
    )
    db.add(cred)
    db.flush()
    row.ephemeral_credential_id = cred.id
    return cred


def _job_credential(
    db: Session,
    run: AuditFlowRun,
    row: AuditFlowHost,
    flow_cred: AuditFlowCredential,
    host: Host | None,
) -> Credential:
    if row.ephemeral_credential_id:
        cred = db.get(Credential, row.ephemeral_credential_id)
        if cred:
            return cred
    if host and host.credential_id:
        inventory_cred = db.get(Credential, host.credential_id)
        if (
            inventory_cred
            and _is_durable_catalog_credential(inventory_cred)
            and (inventory_cred.username or "") == flow_cred.username
        ):
            return inventory_cred
    return _make_ephemeral_credential(db, run, row, flow_cred)


def _ensure_job_target(
    db: Session, run: AuditFlowRun, row: AuditFlowHost
) -> tuple[Host, Credential]:
    flow_cred = next((c for c in run.credentials if c.id == row.credential_id), None)
    if flow_cred is None:
        raise ValueError("Credential missing")

    if row.ephemeral_host_id:
        host = db.get(Host, row.ephemeral_host_id)
        if host:
            cred = _job_credential(db, run, row, flow_cred, host)
            if getattr(cred, "is_ephemeral", False):
                host.credential_id = cred.id
            if row.ssh_known_hosts_entry and not host.ssh_known_hosts_entry:
                host.ssh_known_hosts_entry = row.ssh_known_hosts_entry
                host.ssh_host_key_fingerprint = row.ssh_host_key_fingerprint
            db.flush()
            return host, cred

    existing = _find_inventory_host(
        db,
        run.owner_sub,
        row.ip_address,
        row.hostname,
        row.ssh_host_key_fingerprint,
    )
    inventory_cred = None
    if existing and existing.credential_id:
        inventory_cred = db.get(Credential, existing.credential_id)

    reuse_host = bool(
        existing
        and (
            inventory_cred is None
            or not _is_durable_catalog_credential(inventory_cred)
            or (inventory_cred.username or "") == flow_cred.username
        )
    )

    ports = [int(p) for p in (row.open_ports or "").split(",") if p.strip().isdigit()]
    port = 22
    os_type = row.platform or "linux"
    if os_type == "windows":
        for candidate in (5985, 5986, 445, 3389):
            if candidate in ports:
                port = candidate
                break
        else:
            port = 5985
    elif os_type == "network":
        port = 22 if 22 in ports else (ports[0] if ports else 22)
    elif 22 in ports:
        port = 22

    if reuse_host and existing:
        host = existing
        cred = _job_credential(db, run, row, flow_cred, host)
        if getattr(cred, "is_ephemeral", False):
            host.credential_id = cred.id
        if row.ssh_known_hosts_entry and not host.ssh_known_hosts_entry:
            host.ssh_known_hosts_entry = row.ssh_known_hosts_entry
            host.ssh_host_key_fingerprint = row.ssh_host_key_fingerprint
        if os_type and not host.os_type:
            host.os_type = os_type
        row.ephemeral_host_id = host.id
        db.flush()
        return host, cred

    cred = _job_credential(db, run, row, flow_cred, None)
    host = Host(
        name=f"af-{run.id}-{row.ip_address}"[:128],
        hostname=row.ip_address,
        port=port,
        os_type=os_type,
        credential_id=cred.id,
        is_active=True,
        is_ephemeral=not bool(getattr(run, "save_to_inventory", False)),
        ssh_host_key_fingerprint=row.ssh_host_key_fingerprint,
        ssh_known_hosts_entry=row.ssh_known_hosts_entry,
        owner_sub=run.owner_sub,
    )
    db.add(host)
    db.flush()
    row.ephemeral_host_id = host.id
    return host, cred


def _playbook_for_profile(db: Session, profile_id: int) -> Playbook | None:
    return (
        db.execute(
            select(Playbook).where(
                Playbook.profile_id == profile_id,
                Playbook.kind == PlaybookKind.COMPLIANCE_TEMPLATE,
                Playbook.is_active.is_(True),
            )
        )
        .scalars()
        .first()
    )


def _primary_audit_script(db: Session, profile_id: int) -> CheckScript | None:
    scripts = list(
        db.execute(
            select(CheckScript).where(
                CheckScript.profile_id == profile_id,
                CheckScript.script_kind == ScriptKind.AUDIT,
            )
        )
        .scalars()
        .all()
    )
    active = select_active_scripts(scripts)
    return active[0] if active else None


def _launch_profile_job(
    db: Session,
    run: AuditFlowRun,
    row: AuditFlowHost,
    *,
    profile_id: int,
    host: Host,
) -> tuple[JobRun, int]:
    playbook = _playbook_for_profile(db, profile_id)
    execution_type = None
    if playbook is None:
        audit_script = _primary_audit_script(db, profile_id)
        if audit_script is None:
            raise ValueError("No compliance playbook or audit script for the selected profile")
        execution_type = audit_script.execution_type
    os_type = row.platform or host.os_type or "linux"
    stamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M")
    job = Job(
        name=f"AuditFlow {row.ip_address} ({stamp})"[:256],
        profile_id=profile_id,
        playbook_id=playbook.id if playbook else None,
        execution_type=execution_type,
        is_active=False,
        is_scheduled=False,
        scope=JobScope.NETWORK if os_type == "network" else JobScope.STANDARD,
        owner_sub=run.owner_sub,
    )
    db.add(job)
    db.flush()
    db.add(JobHost(job_id=job.id, host_id=host.id))
    job_run = JobRun(job_id=job.id, status=JobStatus.PENDING)
    db.add(job_run)
    db.flush()
    outbox = enqueue_outbox_row(
        db,
        task_name="app.tasks.run_compliance_job",
        args=[job_run.id],
        queue="compliance",
        callback_kind="job_run",
        callback_ref_id=job_run.id,
        correlation={
            "started_by_sub": run.owner_sub or "system:audit-flow",
            "audit_flow_run_id": run.id,
            "source": "auto_execute",
        },
    )
    return job_run, outbox.id


def _launch_host_checks(db: Session, run: AuditFlowRun, row: AuditFlowHost) -> list[int]:
    host, _cred = _ensure_job_target(db, run, row)
    outbox_ids: list[int] = []
    if row.profile_id and not row.job_run_id:
        job_run, outbox_id = _launch_profile_job(
            db, run, row, profile_id=row.profile_id, host=host
        )
        row.job_run_id = job_run.id
        row.skip_reason = "checking"
        row.skip_detail = None
        outbox_ids.append(outbox_id)

    extra_runs = list(row.extra_runs_json or [])
    launched_profiles = {int(item["profile_id"]) for item in extra_runs if item.get("profile_id")}
    extras = []
    for item in row.extra_profiles_json or []:
        extras.append(dict(item))
        if not item.get("selected"):
            continue
        profile_id = int(item["profile_id"])
        if profile_id in launched_profiles or profile_id == row.profile_id:
            continue
        job_run, outbox_id = _launch_profile_job(
            db, run, row, profile_id=profile_id, host=host
        )
        extra_runs.append(
            {
                "profile_id": profile_id,
                "profile_name": item.get("profile_name") or item.get("label"),
                "job_run_id": job_run.id,
            }
        )
        launched_profiles.add(profile_id)
        outbox_ids.append(outbox_id)
    row.extra_profiles_json = extras
    row.extra_runs_json = extra_runs
    return outbox_ids


def run_audit_flow_execute_sync(run_id: int, *, database_url: str, redis_url: str) -> dict:
    """Launch compliance for selected high-confidence hosts on a READY run."""
    del redis_url  # reserved for cancel/progress parity with scan/reprobe
    engine = create_engine(database_url)
    SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)
    launched = 0
    try:
        with SessionLocal() as db:
            run = db.execute(
                select(AuditFlowRun)
                .options(
                    selectinload(AuditFlowRun.hosts),
                    selectinload(AuditFlowRun.credentials),
                )
                .where(AuditFlowRun.id == run_id)
            ).scalar_one_or_none()
            if run is None:
                return {"audit_flow_run_id": run_id, "launched": 0, "error": "not_found"}
            if run.status != AuditFlowStatus.READY:
                return {
                    "audit_flow_run_id": run_id,
                    "launched": 0,
                    "skipped": True,
                    "reason": f"status_{run.status.value if hasattr(run.status, 'value') else run.status}",
                }

            selected = [h for h in run.hosts if h.selected]
            for row in run.hosts:
                if row.selected or row.job_run_id:
                    continue
                if not row.skip_reason:
                    row.skip_reason = "skipped_by_user"
                    row.skip_detail = "Not selected for compliance"

            run.status = AuditFlowStatus.RUNNING
            run.finished_at = None
            db.flush()
            _log(run_id, f"Auto-execute: starting checks for {len(selected)} selected host(s)")

            for row in selected:
                launched_extra_ids = {
                    int(item["profile_id"])
                    for item in (row.extra_runs_json or [])
                    if item.get("profile_id")
                }
                pending_extras = [
                    item
                    for item in (row.extra_profiles_json or [])
                    if item.get("selected")
                    and item.get("profile_id") is not None
                    and int(item["profile_id"]) not in launched_extra_ids
                    and (row.profile_id is None or int(item["profile_id"]) != row.profile_id)
                ]
                if row.job_run_id and not pending_extras:
                    continue
                if not row.job_run_id and not row.profile_id and not pending_extras:
                    row.skip_reason = "no_matching_profile"
                    row.skip_detail = "No compliance profile selected"
                    continue
                if not row.credential_id:
                    row.skip_reason = "auth_failed"
                    row.skip_detail = "No working credential pair"
                    continue
                try:
                    outbox_ids = _launch_host_checks(db, run, row)
                    launched += len(outbox_ids)
                except Exception as exc:
                    row.skip_reason = "playbook_failed"
                    row.skip_detail = str(exc)[:1000]
                    _log(run_id, f"{row.ip_address}: auto-execute failed — {exc}", level="warning")

            if all(job_run_ids_for_host(h) or h.skip_reason for h in run.hosts):
                if not any(job_run_ids_for_host(h) for h in run.hosts):
                    run.status = AuditFlowStatus.COMPLETED
                    run.finished_at = datetime.now(UTC)
                    _log(run_id, "Auto-execute finished with no jobs launched")
            db.commit()
            return {"audit_flow_run_id": run_id, "launched": launched}
    finally:
        engine.dispose()
