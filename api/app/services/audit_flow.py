"""AuditFlow session helpers."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.auth import AuthUser
from app.core.config import settings
from app.core.secrets import encrypt_secret
from app.models import (
    AuditFlowCredential,
    AuditFlowHost,
    AuditFlowRun,
    AuditFlowStatus,
    CheckResult,
    ComplianceWaiver,
    Credential,
    CredentialType,
    Host,
    HostTagLink,
    InventoryScanResult,
    Job,
    JobHost,
    JobRun,
    JobScope,
    JobStatus,
    JobTemplateHost,
    Playbook,
    PlaybookKind,
    RemediationJobHost,
    RemediationResult,
)
from app.services.dispatch import enqueue_run_dispatch
from app.services.object_rbac import assign_host_target_scope, assign_owner
from secaudit_core.audit_flow_present import (
    host_to_read,
    job_run_ids_for_host,
    reprobe_target_ids,
    run_to_read,
)
from secaudit_core.inventory_scan import validate_scan_target
from secaudit_core.reports import build_report_summary_dict

TTL = timedelta(hours=24)
_ALLOWED_CRED_TYPES = {CredentialType.SSH_PASSWORD, CredentialType.SSH_KEY, CredentialType.WINRM}
_AF_EPHEMERAL_DESCRIPTIONS = frozenset({"AuditFlow ephemeral", "AuditFlow inventory"})
_TERMINAL_JOB = {JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED}
_ACTIVE_FLOW = {AuditFlowStatus.PENDING, AuditFlowStatus.SCANNING, AuditFlowStatus.RUNNING}
EDITABLE_STATUSES = frozenset(
    {AuditFlowStatus.READY, AuditFlowStatus.COMPLETED, AuditFlowStatus.CANCELLED}
)
_CLEARABLE_SKIP = {
    "auth_failed",
    "unreachable",
    "no_matching_profile",
    "skipped_by_user",
    "low_confidence",
    "ambiguous_profile",
    "os_mismatch",
    "checking",
}


def validate_targets(targets: list[str]) -> list[str]:
    flattened: list[str] = []
    for item in targets or []:
        for part in re.split(r"[\s,;\r\n]+", str(item).strip()):
            cleaned_part = part.strip()
            if cleaned_part:
                flattened.append(cleaned_part)
    if not flattened:
        raise ValueError("At least one network range is required")
    if len(flattened) > 16:
        raise ValueError("At most 16 scan targets are allowed")
    return [validate_scan_target(item) for item in flattened]


def validate_credentials(items: list[dict]) -> list[dict]:
    if not items:
        return []
    if len(items) > 20:
        raise ValueError("At most 20 credential pairs are allowed")
    cleaned = []
    for index, item in enumerate(items, start=1):
        cred_type = item.get("credential_type")
        if isinstance(cred_type, str):
            cred_type = CredentialType(cred_type)
        if cred_type not in _ALLOWED_CRED_TYPES:
            raise ValueError(f"Unsupported credential type: {item.get('credential_type')}")
        username = (item.get("username") or "").strip()
        secret = str(item.get("secret") or "").replace("\r\n", "\n").rstrip("\n").rstrip("\r")
        if not username or not secret.strip():
            raise ValueError("Each credential needs a username and secret")
        label = (item.get("label") or "").strip() or f"{cred_type.value}-{index}"
        key_passphrase = (item.get("key_passphrase") or "").strip() or None
        service_username = (item.get("service_username") or "").strip() or None
        service_secret = str(item.get("service_secret") or "").strip() or None
        cleaned.append(
            {
                "label": label[:128],
                "credential_type": cred_type,
                "username": username[:128],
                "secret": secret,
                "key_passphrase": key_passphrase,
                "service_username": service_username[:128] if service_username else None,
                "service_secret": service_secret,
            }
        )
    return cleaned


def can_launch_host(row: AuditFlowHost) -> bool:
    return bool(row.selected and row.profile_id and row.credential_id and not row.job_run_id)


def prepare_run_for_execute(run: AuditFlowRun) -> None:
    if run.status in {AuditFlowStatus.COMPLETED, AuditFlowStatus.CANCELLED}:
        run.status = AuditFlowStatus.READY
        run.finished_at = None
        if run.error_message == "Cancelled by user":
            run.error_message = None
    if run.status != AuditFlowStatus.READY:
        raise ValueError("Scan must be ready before starting checks")


def clear_retryable_skip(row: AuditFlowHost) -> None:
    if row.skip_reason in _CLEARABLE_SKIP:
        row.skip_reason = None
        row.skip_detail = None


def apply_host_selection(row: AuditFlowHost, selected: bool) -> None:
    row.selected = selected
    if row.job_run_id:
        return
    if selected:
        if row.skip_reason == "skipped_by_user":
            row.skip_reason = None
            row.skip_detail = None
    else:
        row.skip_reason = "skipped_by_user"
        row.skip_detail = "Not selected for compliance"


async def load_run(db: AsyncSession, run_id: int) -> AuditFlowRun | None:
    result = await db.execute(
        select(AuditFlowRun)
        .options(
            selectinload(AuditFlowRun.hosts).selectinload(AuditFlowHost.credential),
            selectinload(AuditFlowRun.credentials),
        )
        .where(AuditFlowRun.id == run_id)
    )
    return result.scalar_one_or_none()


async def collect_run_summaries(db: AsyncSession, run: AuditFlowRun) -> dict[int, dict]:
    job_run_ids: list[int] = []
    for row in run.hosts or []:
        job_run_ids.extend(job_run_ids_for_host(row))
    if not job_run_ids:
        return {}
    unique_ids = list(dict.fromkeys(job_run_ids))
    runs = (
        await db.execute(select(JobRun).where(JobRun.id.in_(unique_ids)))
    ).scalars().all()
    checks = (
        await db.execute(select(CheckResult).where(CheckResult.job_run_id.in_(unique_ids)))
    ).scalars().all()
    by_run: dict[int, list] = {run_id: [] for run_id in unique_ids}
    for check in checks:
        by_run.setdefault(check.job_run_id, []).append(check)
    payload: dict[int, dict] = {}
    for job_run in runs:
        summary = build_report_summary_dict(job_run.id, by_run.get(job_run.id, []))
        status = job_run.status.value if hasattr(job_run.status, "value") else job_run.status
        summary["job_status"] = status
        summary["error_message"] = job_run.error_message
        payload[job_run.id] = summary
    return payload


async def collect_reused_host_ids(db: AsyncSession, run: AuditFlowRun) -> set[int]:
    host_ids = [h.ephemeral_host_id for h in (run.hosts or []) if h.ephemeral_host_id]
    if not host_ids:
        return set()
    rows = (
        await db.execute(select(Host.id).where(Host.id.in_(host_ids), Host.is_ephemeral.is_(False)))
    ).scalars().all()
    return set(rows)


async def present_run(db: AsyncSession, run: AuditFlowRun) -> dict:
    await refresh_run_status(db, run)
    summaries = await collect_run_summaries(db, run)
    reused = await collect_reused_host_ids(db, run)
    return run_to_read(run, summaries=summaries, reused_host_ids=reused)


async def enqueue_reprobe(
    db: AsyncSession,
    run: AuditFlowRun,
    *,
    credential_id: int | None = None,
    host_ids: list[int] | None = None,
) -> int | None:
    targets = reprobe_target_ids(run, host_ids=host_ids)
    if not targets:
        return None
    run.status = AuditFlowStatus.SCANNING
    for row in run.hosts:
        if row.id in targets:
            row.skip_reason = "checking"
    outbox = await enqueue_run_dispatch(
        db,
        task_name="app.tasks.audit_flow.run_audit_flow_reprobe_task",
        args=[run.id],
        kwargs={"credential_id": credential_id, "host_ids": targets},
        queue="inventory",
        callback_kind="audit_flow_run",
        callback_ref_id=run.id,
        correlation={"audit_flow_run_id": run.id, "reprobe": True},
    )
    return outbox.id


async def cleanup_expired(db: AsyncSession) -> None:
    cutoff = datetime.now(UTC) - TTL
    result = await db.execute(
        select(AuditFlowRun).where(AuditFlowRun.created_at < cutoff).limit(20)
    )
    for run in result.scalars().all():
        await delete_run_artifacts(db, run)
        await db.delete(run)
    await sweep_orphaned_ephemeral_credentials(db)


async def delete_run_artifacts(db: AsyncSession, run: AuditFlowRun) -> None:
    """Drop jobs/checks/ephemeral inventory created by a run before deleting it.

    Completed runs leave check_results and job_runs pointing at ephemeral hosts.
    Deleting those hosts first violates FKs and surfaces as HTTP 500.
    """
    loaded = await load_run(db, run.id)
    if loaded is None:
        return

    job_run_ids = list(dict.fromkeys(id_ for row in loaded.hosts for id_ in job_run_ids_for_host(row)))
    host_ids = [h.ephemeral_host_id for h in loaded.hosts if h.ephemeral_host_id]
    cred_ids = [h.ephemeral_credential_id for h in loaded.hosts if h.ephemeral_credential_id]

    for row in loaded.hosts:
        row.job_run_id = None
        row.ephemeral_host_id = None
        row.ephemeral_credential_id = None
        row.extra_runs_json = None
    await db.flush()

    job_ids: list[int] = []
    if job_run_ids:
        job_ids = list(
            {
                job_id
                for (job_id,) in (
                    await db.execute(select(JobRun.job_id).where(JobRun.id.in_(job_run_ids)))
                ).all()
                if job_id is not None
            }
        )
        await db.execute(delete(CheckResult).where(CheckResult.job_run_id.in_(job_run_ids)))
        await db.execute(delete(JobRun).where(JobRun.id.in_(job_run_ids)))

    if job_ids:
        leftover = {
            job_id
            for (job_id,) in (await db.execute(select(JobRun.job_id).where(JobRun.job_id.in_(job_ids)))).all()
        }
        drop_jobs = [job_id for job_id in job_ids if job_id not in leftover]
        if drop_jobs:
            await db.execute(
                update(ComplianceWaiver).where(ComplianceWaiver.job_id.in_(drop_jobs)).values(job_id=None)
            )
            await db.execute(delete(JobHost).where(JobHost.job_id.in_(drop_jobs)))
            await db.execute(delete(Job).where(Job.id.in_(drop_jobs)))

    ephemeral_ids: list[int] = []
    if host_ids:
        ephemeral_ids = list(
            (
                await db.execute(select(Host.id).where(Host.id.in_(host_ids), Host.is_ephemeral.is_(True)))
            )
            .scalars()
            .all()
        )
    for host_id in ephemeral_ids:
        await _cleanup_ephemeral_host_refs(db, host_id)
        host = await db.get(Host, host_id)
        if host:
            await db.delete(host)
    await db.flush()

    if cred_ids:
        await _delete_ephemeral_credentials(db, cred_ids)


async def _cleanup_ephemeral_host_refs(db: AsyncSession, host_id: int) -> None:
    await db.execute(delete(CheckResult).where(CheckResult.host_id == host_id))
    await db.execute(delete(RemediationResult).where(RemediationResult.host_id == host_id))
    await db.execute(delete(JobHost).where(JobHost.host_id == host_id))
    await db.execute(delete(RemediationJobHost).where(RemediationJobHost.host_id == host_id))
    await db.execute(delete(JobTemplateHost).where(JobTemplateHost.host_id == host_id))
    await db.execute(delete(HostTagLink).where(HostTagLink.host_id == host_id))
    await db.execute(
        update(ComplianceWaiver).where(ComplianceWaiver.host_id == host_id).values(host_id=None)
    )
    await db.execute(
        update(InventoryScanResult).where(InventoryScanResult.host_id == host_id).values(host_id=None)
    )


async def execute_run(db: AsyncSession, user: AuthUser, run: AuditFlowRun) -> tuple[AuditFlowRun, list[int]]:
    prepare_run_for_execute(run)

    selected = [h for h in run.hosts if h.selected]
    skipped = [h for h in run.hosts if not h.selected]
    for row in skipped:
        if row.job_run_id:
            continue
        if not row.skip_reason:
            row.skip_reason = "skipped_by_user"
            row.skip_detail = "Not selected for compliance"

    run.status = AuditFlowStatus.RUNNING
    await db.flush()
    outbox_ids: list[int] = []

    for row in selected:
        launched_extra_ids = {
            int(item["profile_id"])
            for item in (row.extra_runs_json or [])
            if item.get("profile_id")
        }
        pending_extras: list = []
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
            launched = await _launch_host_checks(db, user, run, row)
            outbox_ids.extend(launched)
        except Exception as exc:
            row.skip_reason = "playbook_failed"
            row.skip_detail = str(exc)[:1000]

    if all(job_run_ids_for_host(h) or h.skip_reason for h in run.hosts):
        if not any(job_run_ids_for_host(h) for h in run.hosts):
            run.status = AuditFlowStatus.COMPLETED
            run.finished_at = datetime.now(UTC)
            await cleanup_run_ephemeral_credentials(db, run)
    return run, outbox_ids


async def _has_pending_jobs(db: AsyncSession, run: AuditFlowRun) -> bool:
    for row in run.hosts or []:
        for job_run_id in job_run_ids_for_host(row):
            job_run = await db.get(JobRun, job_run_id)
            if job_run is not None and job_run.status not in _TERMINAL_JOB:
                return True
    return False


async def refresh_run_status(db: AsyncSession, run: AuditFlowRun) -> AuditFlowRun:
    if run.status == AuditFlowStatus.RUNNING:
        pending = False
        for row in run.hosts:
            run_ids = job_run_ids_for_host(row)
            if not run_ids:
                continue
            for job_run_id in run_ids:
                job_run = await db.get(JobRun, job_run_id)
                if job_run is None:
                    continue
                if job_run.status not in _TERMINAL_JOB:
                    pending = True
                    continue
                if job_run_id == row.job_run_id:
                    if job_run.status == JobStatus.FAILED and not row.skip_reason:
                        row.skip_reason = "playbook_failed"
                        row.skip_detail = job_run.error_message
                    if job_run.status == JobStatus.COMPLETED:
                        row.skip_reason = None
        if not pending:
            run.status = AuditFlowStatus.COMPLETED
            run.finished_at = datetime.now(UTC)
    if run.status == AuditFlowStatus.COMPLETED:
        await cleanup_run_ephemeral_credentials(db, run)
    elif run.status in {AuditFlowStatus.CANCELLED, AuditFlowStatus.FAILED} and not await _has_pending_jobs(
        db, run
    ):
        await cleanup_run_ephemeral_credentials(db, run)
    return run


def _is_durable_catalog_credential(cred: Credential | None) -> bool:
    if cred is None:
        return False
    if getattr(cred, "is_ephemeral", None) is not False:
        return False
    return (getattr(cred, "description", None) or "") not in _AF_EPHEMERAL_DESCRIPTIONS


async def _delete_ephemeral_credentials(db: AsyncSession, cred_ids: list[int]) -> None:
    unique_ids = list(dict.fromkeys(cred_ids))
    if not unique_ids:
        return
    await db.execute(update(Host).where(Host.credential_id.in_(unique_ids)).values(credential_id=None))
    await db.flush()
    for cred_id in unique_ids:
        cred = await db.get(Credential, cred_id)
        if cred is None or _is_durable_catalog_credential(cred):
            continue
        await db.delete(cred)


async def cleanup_run_ephemeral_credentials(db: AsyncSession, run: AuditFlowRun) -> None:
    cred_ids = [h.ephemeral_credential_id for h in (run.hosts or []) if h.ephemeral_credential_id]
    if not cred_ids:
        return
    for row in run.hosts or []:
        row.ephemeral_credential_id = None
    await db.flush()
    await _delete_ephemeral_credentials(db, cred_ids)


async def sweep_orphaned_ephemeral_credentials(db: AsyncSession) -> None:
    """Drop leftover AuditFlow credentials that are not needed by an active run."""
    rows = (await db.execute(select(Credential).where(Credential.is_ephemeral.is_(True)))).scalars().all()
    if not rows:
        return
    cred_ids = [cred.id for cred in rows]
    keep = {
        cred_id
        for (cred_id,) in (
            await db.execute(
                select(AuditFlowHost.ephemeral_credential_id)
                .join(AuditFlowRun, AuditFlowHost.run_id == AuditFlowRun.id)
                .where(
                    AuditFlowHost.ephemeral_credential_id.in_(cred_ids),
                    AuditFlowRun.status.in_(_ACTIVE_FLOW),
                )
            )
        ).all()
        if cred_id is not None
    }
    orphans = [cred.id for cred in rows if cred.id not in keep]
    if not orphans:
        return
    await db.execute(
        update(AuditFlowHost)
        .where(AuditFlowHost.ephemeral_credential_id.in_(orphans))
        .values(ephemeral_credential_id=None)
    )
    await _delete_ephemeral_credentials(db, orphans)


async def _find_inventory_host(db: AsyncSession, owner_sub: str | None, ip: str, hostname: str | None) -> Host | None:
    keys = [value.strip().lower() for value in (ip, hostname) if value and value.strip()]
    if not keys:
        return None
    identity = or_(func.lower(Host.hostname).in_(keys), func.lower(Host.name).in_(keys))
    if owner_sub is None:
        owner_match = Host.owner_sub.is_(None)
    else:
        owner_match = or_(Host.owner_sub == owner_sub, Host.owner_sub.is_(None))
    result = await db.execute(
        select(Host).where(identity, owner_match, Host.is_ephemeral.is_(False)).limit(20)
    )
    candidates = list(result.scalars().all())
    if not candidates:
        return None
    same_owner = [host for host in candidates if host.owner_sub == owner_sub]
    return same_owner[0] if same_owner else candidates[0]


def _pin_host_key(host: Host, row: AuditFlowHost) -> None:
    if row.ssh_known_hosts_entry and not host.ssh_known_hosts_entry:
        host.ssh_known_hosts_entry = row.ssh_known_hosts_entry
        host.ssh_host_key_fingerprint = row.ssh_host_key_fingerprint


async def _playbook_for_profile(db: AsyncSession, profile_id: int) -> Playbook:
    playbook_result = await db.execute(
        select(Playbook).where(
            Playbook.profile_id == profile_id,
            Playbook.kind == PlaybookKind.COMPLIANCE_TEMPLATE,
            Playbook.is_active.is_(True),
        )
    )
    playbook = playbook_result.scalars().first()
    if playbook is None:
        raise ValueError("No compliance playbook for the selected profile")
    return playbook


async def _make_ephemeral_credential(
    db: AsyncSession,
    user: AuthUser,
    run: AuditFlowRun,
    row: AuditFlowHost,
    flow_cred: AuditFlowCredential,
) -> Credential:
    name = f"af-{run.id}-{row.id}-{flow_cred.id}"[:128]
    existing = (await db.execute(select(Credential).where(Credential.name == name))).scalar_one_or_none()
    if existing:
        existing.is_ephemeral = True
        existing.description = existing.description or "AuditFlow ephemeral"
        existing.encrypted_secret = flow_cred.encrypted_secret
        existing.encrypted_key_passphrase = flow_cred.encrypted_key_passphrase
        existing.service_username = flow_cred.service_username
        existing.encrypted_service_secret = flow_cred.encrypted_service_secret
        existing.username = flow_cred.username
        existing.credential_type = flow_cred.credential_type
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
    )
    assign_owner(cred, user)
    db.add(cred)
    await db.flush()
    row.ephemeral_credential_id = cred.id
    return cred


async def _job_credential(
    db: AsyncSession,
    user: AuthUser,
    run: AuditFlowRun,
    row: AuditFlowHost,
    flow_cred: AuditFlowCredential,
    host: Host | None,
) -> Credential:
    if row.ephemeral_credential_id:
        cred = await db.get(Credential, row.ephemeral_credential_id)
        if cred:
            return cred
    if host and host.credential_id:
        inventory_cred = await db.get(Credential, host.credential_id)
        if (
            inventory_cred
            and _is_durable_catalog_credential(inventory_cred)
            and (inventory_cred.username or "") == flow_cred.username
        ):
            return inventory_cred
    return await _make_ephemeral_credential(db, user, run, row, flow_cred)


async def _ensure_job_target(
    db: AsyncSession, user: AuthUser, run: AuditFlowRun, row: AuditFlowHost
) -> tuple[Host, Credential]:
    flow_cred = next((c for c in run.credentials if c.id == row.credential_id), None)
    if flow_cred is None:
        raise ValueError("Credential missing")

    if row.ephemeral_host_id:
        host = await db.get(Host, row.ephemeral_host_id)
        if host:
            cred = await _job_credential(db, user, run, row, flow_cred, host)
            if getattr(cred, "is_ephemeral", False):
                host.credential_id = cred.id
            _pin_host_key(host, row)
            await db.flush()
            return host, cred

    existing = await _find_inventory_host(db, run.owner_sub, row.ip_address, row.hostname)
    inventory_cred = None
    if existing and existing.credential_id:
        inventory_cred = await db.get(Credential, existing.credential_id)

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
        cred = await _job_credential(db, user, run, row, flow_cred, host)
        if getattr(cred, "is_ephemeral", False):
            host.credential_id = cred.id
        _pin_host_key(host, row)
        if os_type and not host.os_type:
            host.os_type = os_type
        row.ephemeral_host_id = host.id
        await db.flush()
        return host, cred

    cred = await _job_credential(db, user, run, row, flow_cred, None)
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
    )
    assign_owner(host, user)
    db.add(host)
    await db.flush()
    row.ephemeral_host_id = host.id
    return host, cred


async def _launch_profile_job(
    db: AsyncSession,
    user: AuthUser,
    run: AuditFlowRun,
    row: AuditFlowHost,
    *,
    profile_id: int,
    host: Host,
) -> tuple[JobRun, int]:
    playbook = await _playbook_for_profile(db, profile_id)
    os_type = row.platform or host.os_type or "linux"
    stamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M")
    job = Job(
        name=f"AuditFlow {row.ip_address} ({stamp})"[:256],
        profile_id=profile_id,
        playbook_id=playbook.id,
        is_active=False,
        is_scheduled=False,
        scope=JobScope.NETWORK if os_type == "network" else JobScope.STANDARD,
    )
    assign_owner(job, user)
    assign_host_target_scope(job, user)
    db.add(job)
    await db.flush()
    db.add(JobHost(job_id=job.id, host_id=host.id))
    job_run = JobRun(job_id=job.id, status=JobStatus.PENDING)
    db.add(job_run)
    await db.flush()
    outbox = await enqueue_run_dispatch(
        db,
        task_name="app.tasks.run_compliance_job",
        args=[job_run.id],
        queue="compliance",
        callback_kind="job_run",
        callback_ref_id=job_run.id,
        correlation={"started_by_sub": user.sub, "audit_flow_run_id": run.id},
    )
    return job_run, outbox.id


async def _launch_host_checks(
    db: AsyncSession, user: AuthUser, run: AuditFlowRun, row: AuditFlowHost
) -> list[int]:
    host, _cred = await _ensure_job_target(db, user, run, row)
    outbox_ids: list[int] = []
    if row.profile_id and not row.job_run_id:
        job_run, outbox_id = await _launch_profile_job(
            db, user, run, row, profile_id=row.profile_id, host=host
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
        job_run, outbox_id = await _launch_profile_job(
            db, user, run, row, profile_id=profile_id, host=host
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


def encrypt_flow_secret(secret: str) -> str:
    return encrypt_secret(secret, settings)
