import logging
import re
import time
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.celery_app import celery_app, settings
from app.tasks.compliance import SessionLocal, _credential_secret, _primary_credential
from secaudit_core.credential_auth import ssh_auth_from_credential
from secaudit_core.beat_lock import acquire_beat_lock, release_beat_lock
from secaudit_core.celery_reliability import TASK_RETRY_KWARGS
from secaudit_core.package_paths import resolve_script_under_package
from secaudit_core.profile_packages import rule_identity_keys
from secaudit_core.script_subset import materialize_subset_script, normalize_allowed_ids
from secaudit_core.transient import reraise_if_transient
from secaudit_core.models import (
    CheckResult,
    CheckScript,
    CheckStatus,
    ExecutionType,
    Host,
    Job,
    JobRun,
    JobStatus,
    MaintenanceWindow,
    NetworkRemediationConfig,
    RemediationJob,
    RemediationResult,
    RemediationRun,
    Rule,
    ScriptKind,
    Profile,
)
from secaudit_core.maintenance_windows import remediation_blocked_by_windows
from secaudit_core.remediation_backup import ticket_envs
from secaudit_core.job_run_subset import classify_host_outcomes, resolve_subset_host_ids
from secaudit_core.enums import JobScope
from secaudit_core.network_vendor_registry import resolve_host_vendor
from secaudit_core.network_config import generate_remediation_config
from app.host_lock_guard import hold_host_lock, host_tcp_ready, wrap_process_host
from app.host_parallel import run_hosts_parallel
from app.logging_pub import publish_remediation_log
from app.notify import emit_run_notification
from secaudit_core.hosts import load_active_hosts, resolve_remediation_host_ids
from secaudit_core.run_state import claim_pending_run, current_run_status, transition_running_run
from secaudit_core.interpreter import parse_jsonl_remediation_lines
from secaudit_core.profile_packages import package_supports_check_mode
from secaudit_core.result_upsert import upsert_remediation_result
from secaudit_core.script_selection import select_active_scripts
from secaudit_core.task_outbox import enqueue_outbox_row
from secaudit_core.tracing import set_current_span_attributes

logger = logging.getLogger(__name__)

HOST_BUSY_MESSAGE = "Host locked by another job or remediation run"
HOST_UNREACHABLE_SCRIPT = "HOST_UNREACHABLE"


def _skip_remediation_host_busy(remediation_run_id: int, host: Host) -> tuple[int, list[str]]:
    with SessionLocal() as host_db:
        publish_remediation_log(
            remediation_run_id,
            f"SKIP [{host.name}]: {HOST_BUSY_MESSAGE}",
            level="warning",
        )
        upsert_remediation_result(
            host_db,
            remediation_run_id=remediation_run_id,
            host_id=host.id,
            script_name="HOST_BUSY",
            status=CheckStatus.SKIP,
            message=HOST_BUSY_MESSAGE,
        )
        host_db.commit()
    return 1, []


def _skip_remediation_host_unreachable(
    remediation_run_id: int, host: Host, detail: str
) -> tuple[int, list[str]]:
    message = f"Host unreachable before run: {detail}"
    with SessionLocal() as host_db:
        publish_remediation_log(
            remediation_run_id,
            f"SKIP [{host.name}]: {message}",
            level="warning",
        )
        upsert_remediation_result(
            host_db,
            remediation_run_id=remediation_run_id,
            host_id=host.id,
            script_name=HOST_UNREACHABLE_SCRIPT,
            status=CheckStatus.SKIP,
            message=message[:500],
        )
        host_db.commit()
    return 1, []


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
    hosts = load_active_hosts(db, host_ids)
    if getattr(settings, "demo_mode", False) and hosts:
        from secaudit_core.demo_exec_guard import assert_hostnames_in_demo_cidrs

        assert_hostnames_in_demo_cidrs(
            [host.hostname for host in hosts],
            allowed_cidrs_raw=getattr(settings, "demo_exec_allowed_cidrs", ""),
        )
    return hosts


def _is_run_cancelled(db: Session, remediation_run_id: int) -> bool:
    from secaudit_core.run_cancel import is_run_cancel_requested

    if is_run_cancel_requested(settings.redis_url, "remediation", remediation_run_id):
        return True
    return (
        current_run_status(db, RemediationRun, remediation_run_id) == JobStatus.CANCELLED
    )


def _remediation_extra_env(
    rule_tech_names: list[str] | None,
    *,
    check_mode: bool = False,
) -> dict[str, str] | None:
    env: dict[str, str] = {}
    rules = [str(name).strip() for name in (rule_tech_names or []) if str(name).strip()]
    if rules:
        env["SECAUDIT_REMEDIATE_RULES"] = ",".join(rules)
    if check_mode:
        env["SECAUDIT_CHECK_MODE"] = "1"
    return env or None


def _remediation_ansible_tags(
    db: Session,
    profile_id: int | None,
    rule_tech_names: list[str] | None,
) -> list[str] | None:
    """Tags for ansible --tags: tech_name plus matching scap_rule_id when present."""
    rules = [str(name).strip() for name in (rule_tech_names or []) if str(name).strip()]
    if not rules:
        return None
    tags = list(rules)
    if profile_id is None:
        return tags
    db_rules = db.execute(select(Rule).where(Rule.profile_id == profile_id)).scalars().all()
    expanded = normalize_allowed_ids(rules) or set(rules)
    for rule in db_rules:
        if not rule.scap_rule_id:
            continue
        if rule.tech_name in expanded or any(
            key in expanded for key in rule_identity_keys(rule.tech_name or "")
        ):
            sid = str(rule.scap_rule_id).strip()
            if sid and sid not in tags:
                tags.append(sid)
    return tags


def _store_remediation_script_results(
    db: Session,
    *,
    remediation_run_id: int,
    host_id: int,
    script_name: str,
    output: str,
    raw_limit: int,
    rule_tech_names: list[str] | None,
) -> int:
    """Persist per-rule JSONL rows when present; otherwise one script-level row."""
    parsed = parse_jsonl_remediation_lines(output)
    if rule_tech_names:
        allowed = {str(name).strip() for name in rule_tech_names if str(name).strip()}
        if allowed:
            parsed = [item for item in parsed if item["tech_name"] in allowed]
    raw = output[:raw_limit]
    if parsed:
        for item in parsed:
            upsert_remediation_result(
                db,
                remediation_run_id=remediation_run_id,
                host_id=host_id,
                script_name=script_name,
                rule_tech_name=item["tech_name"],
                status=item["status"],
                message=str(item.get("message") or item["tech_name"])[:500],
                raw_output=raw,
            )
        return len(parsed)
    summary = output.split("\n", 1)[0][:500]
    upsert_remediation_result(
        db,
        remediation_run_id=remediation_run_id,
        host_id=host_id,
        script_name=script_name,
        rule_tech_name="",
        status=CheckStatus.PASS,
        message=summary or "Remediation completed successfully",
        raw_output=raw,
    )
    return 1


def _execute_remediation(
    host: Host,
    package_dir: Path,
    script: CheckScript,
    execution_type: ExecutionType,
    remediation_run_id: int,
    *,
    rule_tech_names: list[str] | None = None,
    check_mode: bool = False,
    extra_env: dict[str, str] | None = None,
    log_label: str = "remediation",
    ansible_tags: list[str] | None = None,
) -> str:
    cred = _primary_credential(host)
    if not cred:
        raise ValueError(f"Host '{host.name}' has no credential assigned")

    secret = _credential_secret(cred)
    username = cred.username or "root"
    password, private_key, key_passphrase = ssh_auth_from_credential(cred, secret, settings)
    merged_env = dict(_remediation_extra_env(rule_tech_names, check_mode=check_mode) or {})
    if extra_env:
        merged_env.update({str(k): str(v) for k, v in extra_env.items() if v is not None})
    extra_env = merged_env or None
    tags = ansible_tags or (
        [str(name).strip() for name in (rule_tech_names or []) if str(name).strip()] or None
    )

    mode_note = " (check mode)" if check_mode else ""
    publish_remediation_log(
        remediation_run_id,
        f"[{host.name}] Running {log_label} {execution_type.value}: {script.script_file}{mode_note}",
    )
    known_hosts_entry = host.ssh_known_hosts_entry
    script_path = resolve_script_under_package(package_dir, script.script_file)
    run_script_path = materialize_subset_script(script_path, rule_tech_names, kind="remediation")
    script_override: str | None = None
    if run_script_path != script_path:
        script_override = run_script_path.read_text(encoding="utf-8", errors="replace")

    try:
        from app.executors.adapter import run_remediation_script

        return run_remediation_script(
            host,
            execution_type,
            cred=cred,
            secret=secret,
            username=username,
            password=password,
            private_key=private_key,
            key_passphrase=key_passphrase,
            package_dir=package_dir,
            script=script,
            run_script_path=run_script_path,
            script_override=script_override,
            extra_env=extra_env,
            check_mode=check_mode,
            tags=tags,
            known_hosts_entry=known_hosts_entry,
        )
    finally:
        if run_script_path != script_path:
            run_script_path.unlink(missing_ok=True)


def _enqueue_failed_host_recheck(db: Session, remediation_job: RemediationJob) -> int | None:
    """Queue a partial compliance JobRun for hosts that failed on the source audit run."""
    source_run_id = remediation_job.source_run_id
    if not source_run_id:
        return None
    source = db.get(JobRun, source_run_id)
    if not source:
        return None
    audit_job = db.get(Job, source.job_id)
    if not audit_job:
        return None

    checks = list(
        db.execute(select(CheckResult).where(CheckResult.job_run_id == source.id)).scalars().all()
    )
    classified = classify_host_outcomes(checks)
    allowed = set(classified["all"])
    if source.host_ids:
        allowed |= {int(host_id) for host_id in source.host_ids if host_id is not None}
    try:
        host_ids = resolve_subset_host_ids(
            subset="failed",
            classified=classified,
            selected_host_ids=None,
            allowed_host_ids=allowed,
        )
    except ValueError:
        return None
    if not host_ids:
        return None

    job_run = JobRun(
        job_id=audit_job.id,
        status=JobStatus.PENDING,
        host_ids=host_ids,
        is_partial=True,
        subset_kind="failed",
        source_run_id=source.id,
    )
    db.add(job_run)
    db.flush()
    enqueue_outbox_row(
        db,
        task_name="app.tasks.run_compliance_job",
        args=[job_run.id],
        queue="compliance",
        callback_kind="job_run",
        callback_ref_id=job_run.id,
        correlation={
            "source": "remediation_auto_recheck",
            "run_kind": "job",
            "run_id": job_run.id,
            "remediation_job_id": remediation_job.id,
        },
    )
    remediation_job.workflow_reaudit_run_id = job_run.id
    db.flush()
    return job_run.id


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
    else:
        scripts = select_active_scripts(scripts)

    if not scripts:
        raise ValueError("No remediation scripts found for this job")

    package_dir = Path(profile.package_path) if profile.package_path else Path(settings.profiles_path)
    remediation_run_id = remediation_run.id
    execution_type = job.execution_type
    raw_limit = _raw_output_limit()
    rule_tech_names = [
        str(name).strip() for name in (job.rule_tech_names or []) if str(name).strip()
    ] or None
    ansible_tags = _remediation_ansible_tags(db, profile.id, rule_tech_names)
    check_mode = bool(getattr(job, "check_mode", False))
    if check_mode and not package_supports_check_mode(package_dir, execution_type):
        raise ValueError(
            "check_mode is not supported for this package/execution type; "
            "set supports_check_mode in description.json (Ansible always allowed)"
        )

    def process_host(host: Host) -> tuple[int, list[str]]:
        with SessionLocal() as host_db:
            if _is_run_cancelled(host_db, remediation_run_id):
                raise InterruptedError("Remediation run cancelled")

            host_results = 0
            host_errors: list[str] = []
            run_row = host_db.get(RemediationRun, remediation_run_id)
            if run_row is not None and (run_row.backup_status or "") != "skipped":
                try:
                    from app.remediation_backup_ops import collect_host_script_backup

                    def _run_backup_script(backup_script: CheckScript) -> str:
                        return _execute_remediation(
                            host,
                            package_dir,
                            backup_script,
                            execution_type,
                            remediation_run_id,
                            rule_tech_names=rule_tech_names,
                            check_mode=False,
                            log_label="backup",
                        )

                    written = collect_host_script_backup(
                        host_db,
                        run=run_row,
                        job=job,
                        host=host,
                        package_dir=package_dir,
                        execute_script=_run_backup_script,
                    )
                    if written:
                        publish_remediation_log(
                            remediation_run_id,
                            f"[{host.name}] Pre-remediation backup script stored {written} artifact(s)",
                        )
                except Exception as exc:
                    reraise_if_transient(exc)
                    publish_remediation_log(
                        remediation_run_id,
                        f"ERROR [{host.name}] backup: {exc}",
                        level="error",
                    )
                    host_errors.append(f"{host.name}: backup failed: {exc}")
                    upsert_remediation_result(
                        host_db,
                        remediation_run_id=remediation_run_id,
                        host_id=host.id,
                        script_name="PRE_REMEDIATION_BACKUP",
                        status=CheckStatus.ERROR,
                        message=str(exc)[:500],
                    )
                    host_results += 1
                    host_db.commit()
                    return host_results, host_errors
            for script in scripts:
                if _is_run_cancelled(host_db, remediation_run_id):
                    raise InterruptedError("Remediation run cancelled")
                try:
                    output = _execute_remediation(
                        host,
                        package_dir,
                        script,
                        execution_type,
                        remediation_run_id,
                        rule_tech_names=rule_tech_names,
                        check_mode=check_mode,
                        ansible_tags=ansible_tags,
                    )
                    host_results += _store_remediation_script_results(
                        host_db,
                        remediation_run_id=remediation_run_id,
                        host_id=host.id,
                        script_name=script.name,
                        output=output,
                        raw_limit=raw_limit,
                        rule_tech_names=rule_tech_names,
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
                        rule_tech_name="",
                        status=CheckStatus.ERROR,
                        message=message.split("\n", 1)[0][:500],
                        raw_output=message[:raw_limit],
                    )
                    host_results += 1

            host_db.commit()
            return host_results, host_errors

    host_results = run_hosts_parallel(
        hosts,
        settings.job_host_concurrency_for(len(hosts)),
        wrap_process_host(
            settings,
            process_host,
            label=f"remediation_run:{remediation_run_id}",
            on_busy=lambda host: _skip_remediation_host_busy(remediation_run_id, host),
            on_unreachable=lambda host, detail: _skip_remediation_host_unreachable(
                remediation_run_id, host, detail
            ),
        ),
        should_cancel=lambda: _is_run_cancelled(db, remediation_run_id),
    )
    results_count = sum(count for count, _ in host_results)
    errors = [err for _, errs in host_results for err in errs]
    return results_count, errors


def _commands_from_remediation_script(
    package_dir: Path,
    script: CheckScript,
    *,
    rule_tech_names: list[str] | None = None,
) -> list[str]:
    script_path = resolve_script_under_package(package_dir, script.script_file)
    text = script_path.read_text(encoding="utf-8", errors="replace")
    allowed = normalize_allowed_ids(rule_tech_names)
    rule_header = re.compile(r"^#\s*(?:SECAUDIT_RULE_BEGIN\s+)?(RULE\d+)\b", re.IGNORECASE)
    has_markers = any(rule_header.match(line.strip()) for line in text.splitlines())
    if allowed is None or not has_markers:
        return [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    commands: list[str] = []
    current_ok = False
    for line in text.splitlines():
        stripped = line.strip()
        header = rule_header.match(stripped)
        if header:
            rid = header.group(1).upper()
            current_ok = rid in allowed or any(k in allowed for k in rule_identity_keys(rid))
            continue
        if not stripped or stripped.startswith("#"):
            continue
        if current_ok:
            commands.append(stripped)
    return commands


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
    else:
        scripts = select_active_scripts(scripts)

    package_dir = Path(profile.package_path) if profile.package_path else Path(settings.profiles_path)
    remediation_run_id = remediation_run.id
    results_count = 0
    errors: list[str] = []

    for host in hosts:
        if _is_run_cancelled(db, remediation_run_id):
            break
        ok, detail = host_tcp_ready(host)
        if not ok:
            skipped, _ = _skip_remediation_host_unreachable(
                remediation_run_id, host, detail
            )
            results_count += skipped
            continue
        with hold_host_lock(
            settings, host.id, label=f"remediation_run:{remediation_run_id}"
        ) as acquired:
            if not acquired:
                skipped, _ = _skip_remediation_host_busy(remediation_run_id, host)
                results_count += skipped
                continue
            rule_tech_names = [
                str(name).strip() for name in (job.rule_tech_names or []) if str(name).strip()
            ] or None
            commands: list[str] = []
            for script in scripts:
                try:
                    commands.extend(
                        _commands_from_remediation_script(
                            package_dir, script, rule_tech_names=rule_tech_names
                        )
                    )
                except Exception as exc:
                    reraise_if_transient(exc)
                    errors.append(
                        f"{host.name}: failed to read remediation script {script.name}: {exc}"
                    )
            if not commands:
                upsert_remediation_result(
                    db,
                    remediation_run_id=remediation_run_id,
                    host_id=host.id,
                    script_name="network_remediation_config",
                    status=CheckStatus.SKIP,
                    message="No remediation script commands; refusing vendor-specific defaults",
                    raw_output="",
                )
                publish_remediation_log(
                    remediation_run_id,
                    f"[{host.name}] Skipped network remediation: no script commands",
                    level="warning",
                )
                results_count += 1
                continue

            try:
                from app.remediation_backup_ops import collect_network_snapshot

                collect_network_snapshot(db, run=remediation_run, host=host)
                publish_remediation_log(
                    remediation_run_id,
                    f"[{host.name}] Captured running-config snapshot before generating rem config",
                )
            except Exception as exc:
                reraise_if_transient(exc)
                upsert_remediation_result(
                    db,
                    remediation_run_id=remediation_run_id,
                    host_id=host.id,
                    script_name="NETWORK_CONFIG_SNAPSHOT",
                    status=CheckStatus.ERROR,
                    message=str(exc)[:500],
                )
                publish_remediation_log(
                    remediation_run_id,
                    f"ERROR [{host.name}] network snapshot: {exc}",
                    level="error",
                )
                results_count += 1
                errors.append(f"{host.name}: snapshot failed: {exc}")
                continue

            vendor = resolve_host_vendor(host)
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

        windows = list(db.execute(select(MaintenanceWindow).where(MaintenanceWindow.enabled.is_(True))).scalars().all())
        blocked = remediation_blocked_by_windows(windows, hosts)
        if blocked:
            transition_running_run(
                db, RemediationRun, remediation_run_id, JobStatus.FAILED, error_message=blocked
            )
            publish_remediation_log(remediation_run_id, blocked, level="error")
            return {"error": "maintenance_window", "message": blocked}

        need_ticket = ticket_envs(settings)
        if need_ticket and any((host.environment or "").strip().lower() in need_ticket for host in hosts):
            if not (remediation_run.change_ticket or "").strip():
                msg = "change_ticket is required for production remediation"
                transition_running_run(
                    db, RemediationRun, remediation_run_id, JobStatus.FAILED, error_message=msg
                )
                return {"error": "change_ticket", "message": msg}

        from app.cancel_context import active_run_scope
        from secaudit_core.run_cancel import clear_run_cancel_state

        active_run_cm = active_run_scope("remediation", remediation_run_id)
        active_run_cm.__enter__()
        try:
            profile = db.get(Profile, job.profile_id)
            if not profile:
                raise ValueError("Profile not found")

            # Mark backup_status before host work (updated after).
            package_dir = Path(profile.package_path) if profile.package_path else Path(settings.profiles_path)
            if job.scope == JobScope.NETWORK:
                remediation_run.backup_status = "ok"
            else:
                from app.remediation_backup_ops import resolve_backup_restore_scripts

                backup_script, restore_script = resolve_backup_restore_scripts(
                    db, profile_id=job.profile_id, execution_type=job.execution_type
                )
                if backup_script and restore_script:
                    remediation_run.backup_status = "ok"
                else:
                    remediation_run.backup_status = "skipped"
                    publish_remediation_log(
                        remediation_run_id,
                        "WARNING: no remediation_backup/restore script pair for this "
                        "profile/execution type; continuing without restore flow",
                        level="warning",
                    )
            db.commit()

            if job.scope == JobScope.NETWORK:
                results_count, errors = _run_network_remediation_job(
                    db, job, remediation_run, profile, hosts
                )
            else:
                results_count, errors = _run_remediation_job(
                    db, job, remediation_run, profile, hosts
                )
            # If any PRE_REMEDIATION_BACKUP errors, mark failed backup.
            backup_err = db.execute(
                select(RemediationResult.id).where(
                    RemediationResult.remediation_run_id == remediation_run_id,
                    RemediationResult.script_name.in_(["PRE_REMEDIATION_BACKUP", "NETWORK_CONFIG_SNAPSHOT"]),
                    RemediationResult.status == CheckStatus.ERROR,
                ).limit(1)
            ).scalar_one_or_none()
            run_fresh = db.get(RemediationRun, remediation_run_id)
            if run_fresh and backup_err:
                run_fresh.backup_status = "failed"
                db.commit()

            if _is_run_cancelled(db, remediation_run_id):
                transition_running_run(
                    db, RemediationRun, remediation_run_id, JobStatus.CANCELLED
                )
                publish_remediation_log(remediation_run_id, "Remediation run cancelled")
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

            recheck_run_id = None
            want_recheck = bool(getattr(job, "auto_recheck_failed", False)) and not bool(
                getattr(job, "check_mode", False)
            )
            if final_status == JobStatus.COMPLETED and want_recheck:
                try:
                    fresh_job = db.get(RemediationJob, job.id) or job
                    recheck_run_id = _enqueue_failed_host_recheck(db, fresh_job)
                    if recheck_run_id:
                        db.commit()
                        publish_remediation_log(
                            remediation_run_id,
                            f"Queued failed-host recheck JobRun #{recheck_run_id}",
                        )
                except Exception:
                    logger.warning(
                        "Failed to enqueue auto-recheck after remediation_run=%s",
                        remediation_run_id,
                        exc_info=True,
                    )

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
            result = {
                "remediation_run_id": remediation_run_id,
                "status": remediation_run.status.value,
            }
            if recheck_run_id:
                result["reaudit_run_id"] = recheck_run_id
            return result

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
        finally:
            active_run_cm.__exit__(None, None, None)
            clear_run_cancel_state(settings.redis_url, "remediation", remediation_run_id)


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


@celery_app.task(
    bind=True,
    name="app.tasks.run_remediation_rollback",
    **TASK_RETRY_KWARGS,
)
def run_remediation_rollback(self, remediation_run_id: int, host_id: int | None = None, **_kwargs) -> dict:
    """Run remediation_restore scripts for linux/windows hosts. Network is download-only."""
    from app.remediation_backup_ops import restore_host_via_script

    with SessionLocal() as db:
        run = db.get(RemediationRun, remediation_run_id)
        if not run:
            return {"error": "not_found"}
        if run.backup_status != "ok":
            return {"error": "no_backup", "backup_status": run.backup_status}
        job = db.get(RemediationJob, run.remediation_job_id)
        if not job:
            return {"error": "job_not_found"}
        if job.scope == JobScope.NETWORK:
            return {"error": "network_snapshot_only"}
        profile = db.get(Profile, job.profile_id)
        if not profile:
            return {"error": "profile_not_found"}
        package_dir = Path(profile.package_path) if profile.package_path else Path(settings.profiles_path)
        hosts = _resolve_remediation_hosts(db, job)
        if host_id is not None:
            hosts = [host for host in hosts if host.id == host_id]
        results: list[dict] = []
        for host in hosts:
            def _run_restore(restore_script: CheckScript, *, extra_env: dict[str, str] | None = None) -> str:
                return _execute_remediation(
                    host,
                    package_dir,
                    restore_script,
                    job.execution_type,
                    remediation_run_id,
                    rule_tech_names=None,
                    check_mode=False,
                    extra_env=extra_env,
                    log_label="restore",
                )

            results.extend(
                restore_host_via_script(
                    db,
                    run=run,
                    host=host,
                    job=job,
                    package_dir=package_dir,
                    execute_script=_run_restore,
                )
            )
            publish_remediation_log(
                remediation_run_id,
                f"[{host.name}] Rollback finished for host",
            )
        run.rollback_results_json = {"items": results}
        db.commit()
        return {"remediation_run_id": remediation_run_id, "results": results}
