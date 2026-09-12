import logging
import time
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.celery_app import celery_app, settings
from app.tasks.compliance import SessionLocal, _credential_secret
from secaudit_core.credential_auth import ssh_auth_from_credential
from secaudit_core.beat_lock import acquire_beat_lock, release_beat_lock
from secaudit_core.celery_reliability import TASK_RETRY_KWARGS
from secaudit_core.package_paths import resolve_script_under_package
from secaudit_core.transient import reraise_if_transient
from secaudit_core.models import (
    CheckScript,
    CheckStatus,
    CredentialType,
    ExecutionType,
    Host,
    JobStatus,
    NetworkRemediationConfig,
    RemediationJob,
    RemediationResult,
    RemediationRun,
    ScriptKind,
    Profile,
)
from secaudit_core.enums import JobScope, NetworkVendor
from secaudit_core.network_config import generate_remediation_config
from secaudit_core.network_scope import host_is_network
from app.executors.ansible_exec import run_playbook
from app.executors.python_exec import (
    run_script_locally_with_resource_env,
    run_script_over_ssh as run_python_over_ssh,
)
from app.executors.ssh import run_package_script_over_ssh, run_script_over_ssh
from app.executors.winrm_exec import run_script_over_winrm
from app.host_parallel import run_hosts_parallel
from app.logging_pub import publish_remediation_log
from app.notify import emit_run_notification
from secaudit_core.hosts import load_active_hosts, resolve_remediation_host_ids
from secaudit_core.run_state import claim_pending_run, current_run_status, transition_running_run
from secaudit_core.result_upsert import upsert_remediation_result
from secaudit_core.task_outbox import enqueue_outbox_row
from secaudit_core.tracing import set_current_span_attributes

logger = logging.getLogger(__name__)


def _raw_output_limit() -> int:
    return settings.raw_output_max_chars


def _resolve_remediation_hosts(db: Session, job: RemediationJob) -> list[Host]:
    host_ids = resolve_remediation_host_ids(
        db,
        job.id,
        job.dynamic_filter,
        owner_sub=job.owner_sub,
        enforce_owner_scope=job.enforce_host_owner_scope,
    )
    return load_active_hosts(db, host_ids)


def _is_run_cancelled(db: Session, remediation_run_id: int) -> bool:
    return (
        current_run_status(db, RemediationRun, remediation_run_id) == JobStatus.CANCELLED
    )


def _execute_remediation(
    host: Host,
    package_dir: Path,
    script: CheckScript,
    execution_type: ExecutionType,
    remediation_run_id: int,
) -> str:
    if not host.credential:
        raise ValueError(f"Host '{host.name}' has no credential assigned")

    cred = host.credential
    secret = _credential_secret(cred)
    username = cred.username or "root"
    password, private_key, key_passphrase = ssh_auth_from_credential(cred, secret, settings)

    publish_remediation_log(
        remediation_run_id,
        f"[{host.name}] Running remediation {execution_type.value}: {script.script_file}",
    )
    known_hosts_entry = host.ssh_known_hosts_entry

    if execution_type == ExecutionType.WINRM:
        script_path = resolve_script_under_package(package_dir, script.script_file)
        return run_script_over_winrm(
            hostname=host.hostname,
            port=host.port,
            username=username,
            password=secret if cred.credential_type == CredentialType.WINRM else None,
            script_path=script_path,
            server_cert_validation=settings.winrm_server_cert_validation_effective,
        )

    if execution_type == ExecutionType.PYTHON:
        script_path = resolve_script_under_package(package_dir, script.script_file)
        if host_is_network(host):
            return run_script_locally_with_resource_env(
                hostname=host.hostname.strip(),
                port=host.port or 22,
                username=username,
                password=password,
                private_key=private_key,
                script_path=script_path,
                key_passphrase=key_passphrase,
                package_root=package_dir,
            )
        return run_python_over_ssh(
            hostname=host.hostname,
            port=host.port or 22,
            username=username,
            password=password,
            private_key=private_key,
            script_path=script_path,
            known_hosts_entry=known_hosts_entry,
            key_passphrase=key_passphrase,
        )

    if execution_type == ExecutionType.ANSIBLE:
        script_path = resolve_script_under_package(package_dir, script.script_file)
        content = script_path.read_text(encoding="utf-8", errors="replace")
        inv = [
            {
                "name": host.name.strip(),
                "hostname": host.hostname.strip(),
                "port": host.port or 22,
                "ansible_vars": {},
                "ssh_known_hosts_entry": known_hosts_entry,
            }
        ]
        creds: dict = {"username": username}
        if cred.credential_type == CredentialType.SSH_PASSWORD:
            creds["password"] = secret
        elif cred.credential_type == CredentialType.SSH_KEY:
            creds["private_key"] = secret
            if key_passphrase:
                creds["key_passphrase"] = key_passphrase
        elif cred.credential_type == CredentialType.WINRM:
            creds["password"] = secret
            inv[0]["ansible_vars"] = {"ansible_connection": "winrm"}
        return run_playbook(content, inv, credentials=creds, connection_mode="auto")

    return run_package_script_over_ssh(
        hostname=host.hostname,
        port=host.port or 22,
        username=username,
        password=password,
        private_key=private_key,
        package_dir=package_dir,
        script_file=script.script_file,
        known_hosts_entry=known_hosts_entry,
        key_passphrase=key_passphrase,
    )


def _run_remediation_job(
    db: Session,
    job: RemediationJob,
    remediation_run: RemediationRun,
    profile: Profile,
    hosts: list[Host],
) -> tuple[int, list[str]]:
    query = select(CheckScript).where(
        CheckScript.profile_id == profile.id,
        CheckScript.script_kind == ScriptKind.REMEDIATION,
        CheckScript.execution_type == job.execution_type,
    )
    scripts = list(db.execute(query).scalars().all())
    if job.remediation_script_id is not None:
        scripts = [script for script in scripts if script.id == job.remediation_script_id]

    if not scripts:
        raise ValueError("No remediation scripts found for this job")

    package_dir = Path(profile.package_path) if profile.package_path else Path(settings.profiles_path)
    remediation_run_id = remediation_run.id
    execution_type = job.execution_type
    raw_limit = _raw_output_limit()

    def process_host(host: Host) -> tuple[int, list[str]]:
        with SessionLocal() as host_db:
            if _is_run_cancelled(host_db, remediation_run_id):
                raise InterruptedError("Remediation run cancelled")

            host_results = 0
            host_errors: list[str] = []
            for script in scripts:
                if _is_run_cancelled(host_db, remediation_run_id):
                    raise InterruptedError("Remediation run cancelled")
                try:
                    output = _execute_remediation(
                        host, package_dir, script, execution_type, remediation_run_id
                    )
                    summary = output.split("\n", 1)[0][:500]
                    upsert_remediation_result(
                        host_db,
                        remediation_run_id=remediation_run_id,
                        host_id=host.id,
                        script_name=script.name,
                        status=CheckStatus.PASS,
                        message=summary or "Remediation completed successfully",
                        raw_output=output[:raw_limit],
                    )
                    publish_remediation_log(
                        remediation_run_id,
                        f"[{host.name}] Remediation script '{script.name}' finished",
                    )
                except InterruptedError:
                    raise
                except Exception as exc:
                    reraise_if_transient(exc)
                    message = str(exc).strip() or "Remediation execution failed"
                    host_errors.append(f"{host.name}: {message.split(chr(10), 1)[0]}")
                    publish_remediation_log(
                        remediation_run_id,
                        f"ERROR [{host.name}] {script.name}: {message}",
                        level="error",
                    )
                    upsert_remediation_result(
                        host_db,
                        remediation_run_id=remediation_run_id,
                        host_id=host.id,
                        script_name=script.name,
                        status=CheckStatus.ERROR,
                        message=message.split("\n", 1)[0][:500],
                        raw_output=message[:raw_limit],
                    )
                host_results += 1

            host_db.commit()
            return host_results, host_errors

    host_results = run_hosts_parallel(
        hosts,
        settings.job_host_concurrency,
        process_host,
        should_cancel=lambda: _is_run_cancelled(db, remediation_run_id),
    )
    results_count = sum(count for count, _ in host_results)
    errors = [err for _, errs in host_results for err in errs]
    return results_count, errors


def _commands_from_remediation_script(package_dir: Path, script: CheckScript) -> list[str]:
    script_path = resolve_script_under_package(package_dir, script.script_file)
    commands: list[str] = []
    for line in script_path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        commands.append(stripped)
    return commands


def _infer_host_vendor(host: Host) -> NetworkVendor:
    for token in (host.name, host.hostname, host.description or ""):
        lowered = token.lower()
        if "junos" in lowered or "juniper" in lowered:
            return NetworkVendor.JUNIPER_JUNOS
        if "nxos" in lowered or "nexus" in lowered:
            return NetworkVendor.CISCO_NXOS
        if "asa" in lowered:
            return NetworkVendor.CISCO_ASA
        if "arista" in lowered or "eos" in lowered:
            return NetworkVendor.ARISTA_EOS
        if "forti" in lowered:
            return NetworkVendor.FORTINET
    return NetworkVendor.CISCO_IOS


def _run_network_remediation_job(
    db: Session,
    job: RemediationJob,
    remediation_run: RemediationRun,
    profile: Profile,
    hosts: list[Host],
) -> tuple[int, list[str]]:
    query = select(CheckScript).where(
        CheckScript.profile_id == profile.id,
        CheckScript.script_kind == ScriptKind.REMEDIATION,
    )
    scripts = list(db.execute(query).scalars().all())
    if job.remediation_script_id is not None:
        scripts = [script for script in scripts if script.id == job.remediation_script_id]

    package_dir = Path(profile.package_path) if profile.package_path else Path(settings.profiles_path)
    remediation_run_id = remediation_run.id
    results_count = 0
    errors: list[str] = []

    default_commands = [
        "aaa new-model",
        "aaa authentication login default local",
        "ip ssh version 2",
        "service password-encryption",
    ]

    for host in hosts:
        if _is_run_cancelled(db, remediation_run_id):
            break
        commands: list[str] = []
        for script in scripts:
            try:
                commands.extend(_commands_from_remediation_script(package_dir, script))
            except Exception as exc:
                reraise_if_transient(exc)
                errors.append(f"{host.name}: failed to read remediation script {script.name}: {exc}")
        if not commands:
            commands = list(default_commands)

        vendor = _infer_host_vendor(host)
        content = generate_remediation_config(vendor, hostname=host.name, commands=commands)
        filename = f"remediation-{remediation_run_id}-{host.name}-{vendor.value}.cfg"
        db.add(
            NetworkRemediationConfig(
                remediation_run_id=remediation_run_id,
                host_id=host.id,
                vendor=vendor,
                filename=filename,
                content=content,
            )
        )
        upsert_remediation_result(
            db,
            remediation_run_id=remediation_run_id,
            host_id=host.id,
            script_name="network_remediation_config",
            status=CheckStatus.PASS,
            message="Remediation config generated; download and apply on device",
            raw_output=content[: _raw_output_limit()],
        )
        publish_remediation_log(
            remediation_run_id,
            f"[{host.name}] Generated downloadable remediation config ({filename})",
        )
        results_count += 1

    db.commit()
    return results_count, errors


@celery_app.task(
    bind=True,
    name="app.tasks.run_remediation_job",
    **TASK_RETRY_KWARGS,
)
def run_remediation_job(self, remediation_run_id: int, **_kwargs) -> dict:
    set_current_span_attributes({"secaudit.remediation_run_id": remediation_run_id})
    remediation_run = None
    for attempt in range(5):
        with SessionLocal() as db:
            remediation_run = db.get(RemediationRun, remediation_run_id)
        if remediation_run:
            break
        if attempt < 4:
            time.sleep(0.2)

    if not remediation_run:
        with SessionLocal() as db:
            stale = db.get(RemediationRun, remediation_run_id)
            if stale:
                if stale.status == JobStatus.PENDING:
                    claim_pending_run(db, RemediationRun, remediation_run_id)
                transition_running_run(
                    db,
                    RemediationRun,
                    remediation_run_id,
                    JobStatus.FAILED,
                    error_message="Worker could not load remediation run record",
                )
        return {"error": "remediation_run not found"}

    with SessionLocal() as db:
        if not claim_pending_run(db, RemediationRun, remediation_run_id):
            status = current_run_status(db, RemediationRun, remediation_run_id)
            return {
                "remediation_run_id": remediation_run_id,
                "status": status.value if status else "not_found",
                "claimed": False,
            }
        remediation_run = db.get(RemediationRun, remediation_run_id)
        if not remediation_run:
            return {"error": "remediation_run not found"}

        job = db.get(RemediationJob, remediation_run.remediation_job_id)
        if not job:
            transition_running_run(
                db,
                RemediationRun,
                remediation_run_id,
                JobStatus.FAILED,
                error_message="Remediation job not found",
            )
            remediation_run = db.get(RemediationRun, remediation_run_id)
            emit_run_notification(
                settings,
                run_kind="remediation",
                run_id=remediation_run_id,
                job_id=remediation_run.remediation_job_id,
                job_name=f"Remediation #{remediation_run.remediation_job_id}",
                status=remediation_run.status,
                error_message=remediation_run.error_message,
                owner_sub=None,
            )
            return {"error": "remediation job not found"}

        publish_remediation_log(remediation_run_id, f"Remediation run #{remediation_run_id} started")

        hosts = _resolve_remediation_hosts(db, job)
        if not hosts:
            publish_remediation_log(remediation_run_id, "No hosts available", level="error")
            transition_running_run(
                db,
                RemediationRun,
                remediation_run_id,
                JobStatus.FAILED,
                error_message="No active hosts assigned to remediation job",
            )
            remediation_run = db.get(RemediationRun, remediation_run_id)
            emit_run_notification(
                settings,
                run_kind="remediation",
                run_id=remediation_run_id,
                job_id=job.id,
                job_name=job.name,
                status=remediation_run.status,
                error_message=remediation_run.error_message,
                owner_sub=job.owner_sub,
            )
            return {"error": "no hosts"}

        try:
            profile = db.get(Profile, job.profile_id)
            if not profile:
                raise ValueError("Profile not found")

            if job.scope == JobScope.NETWORK:
                results_count, errors = _run_network_remediation_job(
                    db, job, remediation_run, profile, hosts
                )
            else:
                results_count, errors = _run_remediation_job(
                    db, job, remediation_run, profile, hosts
                )

            if _is_run_cancelled(db, remediation_run_id):
                publish_remediation_log(remediation_run_id, "Remediation run cancelled")
                db.commit()
                return {"remediation_run_id": remediation_run_id, "status": JobStatus.CANCELLED.value}

            error_results = db.execute(
                select(RemediationResult.id).where(
                    RemediationResult.remediation_run_id == remediation_run.id,
                    RemediationResult.status == CheckStatus.ERROR,
                ).limit(1)
            ).scalar_one_or_none()
            has_errors = error_results is not None or bool(errors)

            final_status = JobStatus.FAILED if has_errors else JobStatus.COMPLETED
            final_error = "; ".join(errors[:5])[:2000] if errors and has_errors else None
            transition_running_run(
                db,
                RemediationRun,
                remediation_run_id,
                final_status,
                error_message=final_error,
            )
            remediation_run = db.get(RemediationRun, remediation_run_id)

            publish_remediation_log(
                remediation_run_id, f"Remediation run finished: {remediation_run.status.value}"
            )
            emit_run_notification(
                settings,
                run_kind="remediation",
                run_id=remediation_run_id,
                job_id=job.id,
                job_name=job.name,
                status=remediation_run.status,
                error_message=remediation_run.error_message,
                owner_sub=job.owner_sub,
            )
            return {"remediation_run_id": remediation_run_id, "status": remediation_run.status.value}

        except InterruptedError:
            transition_running_run(
                db, RemediationRun, remediation_run_id, JobStatus.CANCELLED
            )
            publish_remediation_log(remediation_run_id, "Remediation run cancelled")
            return {"remediation_run_id": remediation_run_id, "status": JobStatus.CANCELLED.value}

        except Exception as exc:
            reraise_if_transient(exc)
            publish_remediation_log(remediation_run_id, f"Remediation failed: {exc}", level="error")
            transition_running_run(
                db,
                RemediationRun,
                remediation_run_id,
                JobStatus.FAILED,
                error_message=str(exc),
            )
            remediation_run = db.get(RemediationRun, remediation_run_id)
            emit_run_notification(
                settings,
                run_kind="remediation",
                run_id=remediation_run_id,
                job_id=job.id,
                job_name=job.name,
                status=remediation_run.status,
                error_message=remediation_run.error_message,
                owner_sub=job.owner_sub,
            )
            return {"remediation_run_id": remediation_run_id, "status": "failed", "error": str(exc)}


@celery_app.task(name="app.tasks.remediation.run_scheduled_remediation_jobs")
def run_scheduled_remediation_jobs() -> dict:
    lock_key = "beat:schedule_lock:remediation"
    lock_client, lock_token = acquire_beat_lock(
        settings.redis_url,
        lock_key,
        ttl_seconds=settings.beat_lock_ttl_seconds,
    )
    if lock_token is None:
        return {"skipped": True, "reason": "lock_not_acquired"}

    try:
        return _run_scheduled_remediation_jobs_locked()
    finally:
        release_beat_lock(lock_client, lock_key, lock_token)


def _run_scheduled_remediation_jobs_locked() -> dict:
    from croniter import croniter

    now = datetime.now(UTC)
    triggered: list[int] = []

    with SessionLocal() as db:
        jobs = db.execute(
            select(RemediationJob).where(
                RemediationJob.is_active.is_(True),
                RemediationJob.is_scheduled.is_(True),
                RemediationJob.cron_expression.isnot(None),
            )
        ).scalars().all()

        for job in jobs:
            try:
                cron = croniter(job.cron_expression, now)
                prev_run = cron.get_prev(datetime)
            except (ValueError, KeyError) as exc:
                logger.warning(
                    "Skipping scheduled remediation job id=%s: invalid cron %r: %s",
                    job.id,
                    job.cron_expression,
                    exc,
                )
                continue

            if job.last_scheduled_at and prev_run <= job.last_scheduled_at.replace(tzinfo=UTC):
                continue

            remediation_run = RemediationRun(
                remediation_job_id=job.id,
                status=JobStatus.PENDING,
            )
            db.add(remediation_run)
            db.flush()
            enqueue_outbox_row(
                db,
                task_name="app.tasks.run_remediation_job",
                args=[remediation_run.id],
                queue="remediation",
                callback_kind="remediation_run",
                callback_ref_id=remediation_run.id,
                correlation={
                    "source": "schedule",
                    "run_kind": "remediation",
                    "run_id": remediation_run.id,
                },
            )

            job.last_scheduled_at = now
            triggered.append(remediation_run.id)

        db.commit()

    return {"triggered_runs": triggered, "count": len(triggered)}
