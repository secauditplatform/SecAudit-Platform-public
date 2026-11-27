"""Collect and restore remediation backup artifacts for a run/host."""

from __future__ import annotations

import base64
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.celery_app import settings
from app.remediation_backup_exec import read_network_running_config
from app.tasks.compliance import _credential_secret, _primary_credential
from secaudit_core.credential_auth import ssh_auth_from_credential
from secaudit_core.models import (
    CheckScript,
    Host,
    RemediationBackupArtifact,
    RemediationJob,
    RemediationRun,
    ScriptKind,
)
from secaudit_core.network_vendor_registry import resolve_host_vendor
from secaudit_core.remediation_backup import load_backup_bytes, store_backup_bytes
from secaudit_core.script_selection import select_active_scripts


def resolve_backup_restore_scripts(
    db: Session,
    *,
    profile_id: int,
    execution_type,
) -> tuple[CheckScript | None, CheckScript | None]:
    """Return active backup + restore scripts matching the job execution type."""
    backup_rows = list(
        db.execute(
            select(CheckScript).where(
                CheckScript.profile_id == profile_id,
                CheckScript.script_kind == ScriptKind.REMEDIATION_BACKUP,
                CheckScript.execution_type == execution_type,
            )
        )
        .scalars()
        .all()
    )
    restore_rows = list(
        db.execute(
            select(CheckScript).where(
                CheckScript.profile_id == profile_id,
                CheckScript.script_kind == ScriptKind.REMEDIATION_RESTORE,
                CheckScript.execution_type == execution_type,
            )
        )
        .scalars()
        .all()
    )
    backup = (select_active_scripts(backup_rows) or [None])[0]
    restore = (select_active_scripts(restore_rows) or [None])[0]
    if backup is None or restore is None:
        return None, None
    return backup, restore


def collect_host_script_backup(
    db: Session,
    *,
    run: RemediationRun,
    job: RemediationJob,
    host: Host,
    package_dir: Path,
    execute_script,
) -> int:
    """Run package remediation_backup script and store stdout. 0 = skipped (no pair)."""
    backup_script, restore_script = resolve_backup_restore_scripts(
        db, profile_id=job.profile_id, execution_type=job.execution_type
    )
    if backup_script is None or restore_script is None:
        return 0

    output = execute_script(backup_script)
    payload = (output or "").encode("utf-8", errors="replace")
    blob, ref, digest, size = store_backup_bytes(
        payload,
        settings=settings,
        run_id=run.id,
        host_id=host.id,
        path_key=backup_script.script_file,
    )
    platform = "windows" if str(job.execution_type.value).lower() == "winrm" else "linux"
    db.add(
        RemediationBackupArtifact(
            remediation_run_id=run.id,
            host_id=host.id,
            platform=platform,
            kind="script_stdout",
            path_or_key=backup_script.script_file,
            encrypted_blob=blob,
            storage_ref=ref,
            sha256=digest,
            byte_size=size,
        )
    )
    return 1


def collect_network_snapshot(db: Session, *, run: RemediationRun, host: Host) -> int:
    cred = _primary_credential(host)
    if not cred:
        raise ValueError(f"Host '{host.name}' has no credential assigned")
    secret = _credential_secret(cred)
    username = cred.username or "admin"
    password, private_key, key_passphrase = ssh_auth_from_credential(cred, secret, settings)
    vendor = resolve_host_vendor(host)
    payload = read_network_running_config(
        hostname=host.hostname,
        port=host.port or 22,
        username=username,
        password=password,
        private_key=private_key,
        vendor=vendor,
        key_passphrase=key_passphrase,
        known_hosts_entry=host.ssh_known_hosts_entry,
    )
    blob, ref, digest, size = store_backup_bytes(
        payload, settings=settings, run_id=run.id, host_id=host.id, path_key="running-config"
    )
    db.add(
        RemediationBackupArtifact(
            remediation_run_id=run.id,
            host_id=host.id,
            platform="network",
            kind="running_config",
            path_or_key="running-config",
            encrypted_blob=blob,
            storage_ref=ref,
            sha256=digest,
            byte_size=size,
        )
    )
    return 1


def restore_host_via_script(
    db: Session,
    *,
    run: RemediationRun,
    host: Host,
    job: RemediationJob,
    package_dir: Path,
    execute_script,
) -> list[dict]:
    """Run remediation_restore with SECAUDIT_BACKUP_B64 from stored script_stdout artifact."""
    _backup, restore_script = resolve_backup_restore_scripts(
        db, profile_id=job.profile_id, execution_type=job.execution_type
    )
    if restore_script is None:
        return [{"host_id": host.id, "status": "skip", "message": "No restore script"}]

    artifacts = list(
        db.execute(
            select(RemediationBackupArtifact).where(
                RemediationBackupArtifact.remediation_run_id == run.id,
                RemediationBackupArtifact.host_id == host.id,
                RemediationBackupArtifact.kind == "script_stdout",
            )
        )
        .scalars()
        .all()
    )
    if not artifacts:
        return [{"host_id": host.id, "status": "skip", "message": "No backup artifacts"}]

    results: list[dict] = []
    for artifact in artifacts:
        try:
            content = load_backup_bytes(
                encrypted_blob=artifact.encrypted_blob,
                storage_ref=artifact.storage_ref,
                settings=settings,
            )
            b64 = base64.b64encode(content).decode("ascii")
            execute_script(restore_script, extra_env={"SECAUDIT_BACKUP_B64": b64})
            results.append(
                {
                    "host_id": host.id,
                    "path": artifact.path_or_key,
                    "status": "ok",
                }
            )
        except Exception as exc:
            results.append(
                {
                    "host_id": host.id,
                    "path": artifact.path_or_key,
                    "status": "error",
                    "message": str(exc)[:300],
                }
            )
    return results
