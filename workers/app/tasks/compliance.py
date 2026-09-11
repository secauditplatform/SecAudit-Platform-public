import json
import logging
import tempfile
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import create_engine, or_, select
from sqlalchemy.orm import Session, sessionmaker

from app.celery_app import celery_app, settings
from secaudit_core.beat_lock import acquire_beat_lock, release_beat_lock
from secaudit_core.celery_observability import touch_worker_heartbeat
from secaudit_core.celery_reliability import TASK_RETRY_KWARGS
from secaudit_core.package_paths import resolve_script_under_package
from secaudit_core.transient import reraise_if_transient
from secaudit_core.host_credentials import linked_credentials
from secaudit_core.hosts import load_active_hosts, resolve_job_targets
from secaudit_core.interpreter import apply_interpreter_rules
from secaudit_core.oscap import (
    merge_scap_and_script_results,
    resolve_oval_path,
    resolve_scap_benchmark_path,
    resolve_scap_content_files,
    resolve_scap_profile_id,
)
from secaudit_core.tracing import set_current_span_attributes, start_span
from secaudit_core.models import (
    CheckResult,
    CheckScript,
    CheckStatus,
    Credential,
    CredentialType,
    ExecutionType,
    Host,
    InterpreterRule,
    Job,
    JobRun,
    JobStatus,
    NetworkCheckMode,
    NetworkDeviceConfig,
    Playbook,
    Rule,
    ScriptKind,
    Profile,
)
from secaudit_core.enums import CategoryType, JobScope, NetworkVendor
from secaudit_core.network_config import parse_network_config
from secaudit_core.network_scope import host_is_network
from app.executors.ansible_exec import (
    AnsiblePlaybookError,
    extract_script_module_refs,
    load_playbook_sidecar_files,
    run_playbook,
)
from secaudit_core.playbook_compliance import parse_playbook_compliance_checks
from app.executors.oscap_exec import (
    OscapNotAvailableError,
    run_oscap_eval_over_ssh,
    run_oval_eval_over_ssh,
)
from app.executors.python_exec import (
    run_script_locally_with_resource_env,
    run_script_over_ssh as run_script_over_python,
)
from app.executors.ssh import run_script_over_ssh
from app.executors.winrm_exec import run_script_over_winrm
from app.executors.network_exec import fetch_running_config
from app.host_parallel import run_hosts_parallel
from secaudit_core.connectivity_playbook import upgrade_connectivity_check_content
from app.logging_pub import publish_job_log
from app.notify import emit_run_notification
from secaudit_core.credential_auth import ssh_auth_from_credential
from secaudit_core.secrets import decrypt_secret
from secaudit_core.service_credentials import (
    profile_uses_service_credentials,
    service_env_from_credential,
)
from secaudit_core.result_upsert import upsert_check_result
from secaudit_core.run_state import claim_pending_run, current_run_status, transition_running_run
from secaudit_core.task_outbox import enqueue_outbox_row


engine = create_engine(settings.database_url_sync)
SessionLocal = sessionmaker(bind=engine)
logger = logging.getLogger(__name__)


def _raw_output_limit() -> int:
    return settings.raw_output_max_chars


def _safe_status(value: str | CheckStatus) -> CheckStatus:
    if isinstance(value, CheckStatus):
        return value
    try:
        return CheckStatus(value)
    except ValueError:
        return CheckStatus.ERROR


def _upsert_playbook_compliance_checks(
    db: Session,
    *,
    job_run_id: int,
    host_id: int,
    output: str,
) -> list[dict]:
    checks = parse_playbook_compliance_checks(output)
    for item in checks:
        upsert_check_result(
            db,
            job_run_id=job_run_id,
            host_id=host_id,
            rule_tech_name=item["tech_name"],
            status=_safe_status(item["status"]),
            message=item.get("message") or None,
            raw_output=None,
        )
    return checks


def _playbook_shell_message(output: str, checks: list[dict], *, fallback: str) -> str:
    if not checks:
        first = output.split("\n", 1)[0].strip()
        return (first or fallback)[:500]
    passed = sum(1 for item in checks if item["status"] == CheckStatus.PASS)
    failed = sum(1 for item in checks if item["status"] == CheckStatus.FAIL)
    skipped = sum(1 for item in checks if item["status"] == CheckStatus.SKIP)
    errored = sum(1 for item in checks if item["status"] == CheckStatus.ERROR)
    parts = [f"{passed} passed", f"{failed} failed"]
    if skipped:
        parts.append(f"{skipped} skipped")
    if errored:
        parts.append(f"{errored} errors")
    return f"{', '.join(parts)} ({len(checks)} checks)"[:500]


def _persist_playbook_host_results(
    db: Session,
    *,
    job_run_id: int,
    host_id: int,
    output: str,
    raw_limit: int,
    ok: bool,
    error_message: str | None = None,
) -> int:
    checks = _upsert_playbook_compliance_checks(
        db,
        job_run_id=job_run_id,
        host_id=host_id,
        output=output,
    )
    fail_count = sum(1 for item in checks if item["status"] == CheckStatus.FAIL)
    error_count = sum(1 for item in checks if item["status"] == CheckStatus.ERROR)

    if ok:
        # Ansible finished, but CRE failures should surface on the host shell row.
        if fail_count or error_count:
            shell_status = CheckStatus.FAIL
        else:
            shell_status = CheckStatus.PASS
        shell_rule = "PLAYBOOK_OK"
        shell_message = _playbook_shell_message(
            output,
            checks,
            fallback="Playbook completed successfully",
        )
    else:
        shell_status = CheckStatus.ERROR
        shell_rule = "PLAYBOOK_ERROR"
        shell_message = (error_message or _playbook_shell_message(output, checks, fallback="Playbook execution failed"))[
            :500
        ]

    upsert_check_result(
        db,
        job_run_id=job_run_id,
        host_id=host_id,
        rule_tech_name=shell_rule,
        status=shell_status,
        message=shell_message,
        raw_output=output[:raw_limit] if output else None,
    )
    return 1 + len(checks)


def _load_interpreter_rules(db: Session, script: CheckScript) -> list[dict]:
    db_rules = db.execute(
        select(InterpreterRule).where(InterpreterRule.check_script_id == script.id)
    ).scalars().all()
    if db_rules:
        return [{"regex": rule.regex, "tech_name": rule.tech_name} for rule in db_rules]
    return []


def _resolve_hosts(db: Session, job: Job) -> list[Host]:
    host_ids = resolve_job_targets(
        db,
        job.id,
        job.dynamic_filter,
        owner_sub=job.owner_sub,
        enforce_owner_scope=job.enforce_host_owner_scope,
    )
    return load_active_hosts(db, host_ids)


def _is_run_cancelled(db: Session, job_run_id: int) -> bool:
    return current_run_status(db, JobRun, job_run_id) == JobStatus.CANCELLED


def _credential_secret(cred: Credential) -> str:
    return decrypt_secret(cred.encrypted_secret, settings)


def _primary_credential(host: Host) -> Credential | None:
    creds = linked_credentials(host)
    return creds[0] if creds else None


def _ssh_auth_tuple(cred: Credential) -> tuple[str, str | None, str | None, str | None]:
    secret = _credential_secret(cred)
    username = cred.username or "root"
    password, private_key, key_passphrase = ssh_auth_from_credential(cred, secret, settings)
    return username, password, private_key, key_passphrase


def _iter_ssh_credentials(host: Host):
    for cred in linked_credentials(host):
        if cred.credential_type not in (CredentialType.SSH_PASSWORD, CredentialType.SSH_KEY):
            continue
        username, password, private_key, key_passphrase = _ssh_auth_tuple(cred)
        if password or private_key:
            yield cred, username, password, private_key, key_passphrase


def _host_known_hosts_entry(host: Host) -> str | None:
    return host.ssh_known_hosts_entry


def _profile_category_type(profile: Profile) -> CategoryType | None:
    category = profile.category
    return category.category_type if category is not None else None


def _service_env_for_profile(host: Host, profile: Profile) -> dict[str, str]:
    """Build service-layer env vars when the profile audits a service (DB, middleware, etc.)."""
    if not profile_uses_service_credentials(_profile_category_type(profile)):
        return {}
    for cred in linked_credentials(host):
        env = service_env_from_credential(cred, settings)
        if env:
            return env
    raise ValueError(
        f"Profile '{profile.profile_name}' requires service credentials "
        "(set service username/password on the host credential)"
    )


def _merge_extra_env(*parts: dict[str, str] | None) -> dict[str, str] | None:
    merged: dict[str, str] = {}
    for part in parts:
        if part:
            merged.update(part)
    return merged or None


def _host_inventory_entry(host: Host) -> dict:
    entry: dict = {
        "name": host.name.strip(),
        "hostname": host.hostname.strip(),
        "port": host.port,
        "ansible_vars": {},
        "ssh_known_hosts_entry": host.ssh_known_hosts_entry,
    }
    if not host.credential and not host.credential_links:
        return entry

    cred = _primary_credential(host)
    if not cred:
        return entry
    secret = _credential_secret(cred)
    if cred.username:
        entry["ansible_vars"]["ansible_user"] = cred.username

    if cred.credential_type == CredentialType.SSH_PASSWORD:
        entry["ansible_vars"]["ansible_password"] = secret
    elif cred.credential_type == CredentialType.SSH_KEY:
        entry["private_key"] = secret
        key_passphrase = ssh_auth_from_credential(cred, secret, settings)[2]
        if key_passphrase:
            entry["key_passphrase"] = key_passphrase
    elif cred.credential_type == CredentialType.WINRM:
        from app.executors.winrm_exec import normalize_winrm_port

        entry["ansible_vars"]["ansible_connection"] = "winrm"
        entry["ansible_vars"]["ansible_password"] = secret
        entry["ansible_vars"]["ansible_winrm_transport"] = "ntlm"
        entry["ansible_vars"]["ansible_winrm_server_cert_validation"] = (
            settings.winrm_server_cert_validation_effective
        )
        entry["port"] = normalize_winrm_port(host.port)

    return entry


def _run_with_progress_logs(
    job_run_id: int,
    host_name: str,
    script_name: str,
    execute,
    *,
    interval_seconds: int = 60,
) -> str:
    """Execute a remote check and emit periodic live-log heartbeats while it runs."""
    result: dict[str, str] = {}
    error: dict[str, BaseException] = {}
    done = threading.Event()

    def _worker() -> None:
        try:
            result["value"] = execute()
        except BaseException as exc:
            error["exc"] = exc
        finally:
            done.set()

    thread = threading.Thread(target=_worker, daemon=True)
    thread.start()

    elapsed_minutes = 0
    while not done.wait(timeout=interval_seconds):
        elapsed_minutes += 1
        publish_job_log(
            job_run_id,
            f"[{host_name}] Still running {script_name} ({elapsed_minutes} min)...",
        )

    thread.join()
    if "exc" in error:
        raise error["exc"]
    return result["value"]


def _execute_check(
    host: Host,
    script_path: Path,
    execution_type: ExecutionType,
    job_run_id: int,
    *,
    extra_env: dict[str, str] | None = None,
) -> str:
    creds = linked_credentials(host)
    cred = creds[0] if creds else None
    has_config_file = bool(extra_env and extra_env.get("SECAUDIT_CONFIG_FILE"))
    if not cred and not (host_is_network(host) and has_config_file and execution_type == ExecutionType.PYTHON):
        raise ValueError(f"Host '{host.name}' has no credential assigned")

    secret = _credential_secret(cred) if cred else None
    username = (cred.username if cred else None) or "root"

    publish_job_log(job_run_id, f"[{host.name}] Running {execution_type.value}: {script_path.name}")
    known_hosts_entry = _host_known_hosts_entry(host)

    def _dispatch() -> str:
        if execution_type == ExecutionType.SSH:
            attempts = list(_iter_ssh_credentials(host))
            if not attempts:
                raise ValueError("SSH requires ssh_password or ssh_key credential")
            last_error: Exception | None = None
            for attempt_cred, attempt_user, password, private_key, key_passphrase in attempts:
                try:
                    return run_script_over_ssh(
                        hostname=host.hostname.strip(),
                        port=host.port,
                        username=attempt_user,
                        password=password,
                        private_key=private_key,
                        script_path=script_path,
                        known_hosts_entry=known_hosts_entry,
                        key_passphrase=key_passphrase,
                        extra_env=extra_env,
                    )
                except Exception as exc:
                    last_error = exc
                    publish_job_log(
                        job_run_id,
                        f"[{host.name}] SSH auth failed with {attempt_cred.name}: {exc}",
                        level="warning",
                    )
            raise last_error or ValueError("SSH authentication failed for all linked credentials")

        if execution_type == ExecutionType.WINRM:
            if not cred or cred.credential_type != CredentialType.WINRM:
                raise ValueError("WinRM checks require winrm credential")
            return run_script_over_winrm(
                hostname=host.hostname.strip(),
                port=host.port,
                username=username,
                password=secret,
                script_path=script_path,
                server_cert_validation=settings.winrm_server_cert_validation_effective,
                extra_env=extra_env,
            )

        if execution_type == ExecutionType.PYTHON:
            password = (
                secret
                if cred and cred.credential_type == CredentialType.SSH_PASSWORD
                else None
            )
            private_key = (
                secret if cred and cred.credential_type == CredentialType.SSH_KEY else None
            )
            key_passphrase = (
                ssh_auth_from_credential(cred, secret, settings)[2]
                if cred and cred.credential_type == CredentialType.SSH_KEY
                else None
            )
            # Network devices cannot run uploaded python3; scripts use Netmiko/Paramiko
            # from the worker with resource_* credentials (Juniper/Cisco ONLINE pattern).
            if host_is_network(host):
                if not password and not private_key and not has_config_file:
                    raise ValueError(
                        "Network Python checks require ssh_password/ssh_key credential "
                        "or an uploaded device config"
                    )
                return run_script_locally_with_resource_env(
                    hostname=host.hostname.strip(),
                    port=host.port or 22,
                    username=username,
                    password=password,
                    private_key=private_key,
                    script_path=script_path,
                    extra_env=extra_env,
                    key_passphrase=key_passphrase,
                )
            if not password and not private_key:
                raise ValueError("Python checks require ssh_password or ssh_key credential")
            return run_script_over_python(
                hostname=host.hostname.strip(),
                port=host.port,
                username=username,
                password=password,
                private_key=private_key,
                script_path=script_path,
                known_hosts_entry=known_hosts_entry,
                key_passphrase=key_passphrase,
                extra_env=extra_env,
            )

        if execution_type == ExecutionType.ANSIBLE:
            if not cred:
                raise ValueError(f"Host '{host.name}' has no credential assigned")
            content = script_path.read_text(encoding="utf-8", errors="replace")
            inv = [_host_inventory_entry(host)]
            creds = {"username": username}
            if cred.credential_type == CredentialType.SSH_PASSWORD:
                creds["password"] = secret
            elif cred.credential_type == CredentialType.SSH_KEY:
                creds["private_key"] = secret
                key_passphrase = ssh_auth_from_credential(cred, secret, settings)[2]
                if key_passphrase:
                    creds["key_passphrase"] = key_passphrase
            return run_playbook(
                content,
                inv,
                credentials=creds,
                connection_mode="auto",
                extravars=extra_env,
            )

        raise NotImplementedError(f"Execution type '{execution_type.value}' is not supported")

    return _run_with_progress_logs(
        job_run_id,
        host.name,
        script_path.name,
        _dispatch,
    )


def _network_script_extra_env(db: Session, job: Job, host: Host) -> dict[str, str]:
    """Inject uploaded config for Network Platform package scripts (file fallback)."""
    mode = job.network_check_mode or NetworkCheckMode.BOTH
    if mode not in {NetworkCheckMode.CONFIG_UPLOAD, NetworkCheckMode.BOTH}:
        return {}

    configs = db.execute(
        select(NetworkDeviceConfig)
        .where(
            NetworkDeviceConfig.job_id == job.id,
            or_(
                NetworkDeviceConfig.host_id == host.id,
                NetworkDeviceConfig.host_id.is_(None),
            ),
        )
        .order_by(NetworkDeviceConfig.id.desc())
    ).scalars().all()
    if not configs:
        return {}

    latest = next((c for c in configs if c.host_id == host.id), configs[0])
    tmp = tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        suffix=".cfg",
        prefix=f"secaudit_netcfg_{host.id}_",
        delete=False,
    )
    with tmp:
        tmp.write(latest.content or "")
    return {
        "SECAUDIT_CONFIG_FILE": tmp.name,
        "SECAUDIT_PREFER_CONFIG_FILE": "1",
    }


def _host_ssh_credentials(host: Host) -> tuple[str, str | None, str | None, str | None]:
    attempts = list(_iter_ssh_credentials(host))
    if not attempts:
        raise ValueError(f"Host '{host.name}' has no credential assigned")
    _, username, password, private_key, key_passphrase = attempts[0]
    return username, password, private_key, key_passphrase


def _run_scap_profile_job(
    db: Session,
    job: Job,
    job_run: JobRun,
    profile: Profile,
    hosts: list[Host],
    package_dir: Path,
    benchmark_path: Path,
    *,
    mode: str = "xccdf",
) -> tuple[int, list[str]]:
    """Evaluate an XCCDF/OVAL profile via OpenSCAP on target hosts (script fallback for SCE)."""
    content_files = (
        [benchmark_path]
        if mode == "oval"
        else resolve_scap_content_files(package_dir, benchmark_path)
    )
    profile_id = (
        resolve_scap_profile_id(package_dir, db_profile_id=profile.scap_profile_id)
        if mode == "xccdf"
        else None
    )
    engine_label = "OVAL" if mode == "oval" else "OpenSCAP"
    result_kind = "oval" if mode == "oval" else "xccdf"

    db_rules = db.execute(select(Rule).where(Rule.profile_id == profile.id)).scalars().all()
    rules_payload = [
        {
            "tech_name": rule.tech_name,
            "scap_rule_id": rule.scap_rule_id,
            "title": rule.title,
        }
        for rule in db_rules
    ]

    scripts = db.execute(
        select(CheckScript).where(
            CheckScript.profile_id == profile.id,
            CheckScript.script_kind == ScriptKind.AUDIT,
        )
    ).scalars().all()
    if job.execution_type is not None:
        scripts = [script for script in scripts if script.execution_type == job.execution_type]
    audit_script = scripts[0] if scripts else None

    job_run_id = job_run.id
    raw_limit = _raw_output_limit()

    def process_host(host: Host) -> tuple[int, list[str]]:
        with SessionLocal() as host_db:
            if _is_run_cancelled(host_db, job_run_id):
                raise InterruptedError("Job run cancelled")

            host_errors: list[str] = []
            scap_outcomes: dict[str, str] = {}
            raw_oscap = ""
            script_parsed: list[dict] = []

            try:
                username, password, private_key, key_passphrase = _host_ssh_credentials(host)
            except ValueError as exc:
                message = str(exc)
                publish_job_log(job_run_id, f"ERROR [{host.name}]: {message}", level="error")
                upsert_check_result(
                    host_db,
                    job_run_id=job_run_id,
                    host_id=host.id,
                    rule_tech_name="EXEC_ERROR",
                    status=CheckStatus.ERROR,
                    message=message,
                )
                host_db.commit()
                return 1, [f"{host.name}: {message}"]

            publish_job_log(
                job_run_id,
                f"[{host.name}] {engine_label} eval: {benchmark_path.name}"
                + (f" (profile {profile_id})" if profile_id else ""),
            )
            try:
                if mode == "oval":
                    scap_outcomes, raw_oscap = run_oval_eval_over_ssh(
                        hostname=host.hostname.strip(),
                        port=host.port,
                        username=username,
                        password=password,
                        private_key=private_key,
                        oval_path=benchmark_path,
                        known_hosts_entry=_host_known_hosts_entry(host),
                        key_passphrase=key_passphrase,
                    )
                else:
                    scap_outcomes, raw_oscap = run_oscap_eval_over_ssh(
                        hostname=host.hostname.strip(),
                        port=host.port,
                        username=username,
                        password=password,
                        private_key=private_key,
                        benchmark_path=benchmark_path,
                        content_files=content_files,
                        profile_id=profile_id,
                        known_hosts_entry=_host_known_hosts_entry(host),
                        key_passphrase=key_passphrase,
                    )
                publish_job_log(
                    job_run_id,
                    f"[{host.name}] {engine_label} returned {len(scap_outcomes)} results",
                )
            except OscapNotAvailableError as exc:
                publish_job_log(job_run_id, f"[{host.name}] {exc}", level="warning")
                host_errors.append(f"{host.name}: {exc}")
            except InterruptedError:
                raise
            except Exception as exc:
                reraise_if_transient(exc)
                message = str(exc).strip() or "OpenSCAP evaluation failed"
                publish_job_log(job_run_id, f"ERROR [{host.name}]: {message}", level="error")
                host_errors.append(f"{host.name}: {message}")

            if audit_script is not None:
                script_path = resolve_script_under_package(package_dir, audit_script.script_file)
                rules = _load_interpreter_rules(host_db, audit_script)
                try:
                    service_env = _service_env_for_profile(host, profile)
                    output = _execute_check(
                        host,
                        script_path,
                        audit_script.execution_type,
                        job_run_id,
                        extra_env=service_env or None,
                    )
                    script_parsed = apply_interpreter_rules(output, rules)
                except InterruptedError:
                    raise
                except Exception as exc:
                    reraise_if_transient(exc)
                    host_errors.append(f"{host.name}: script fallback failed: {exc}")
                    publish_job_log(
                        job_run_id,
                        f"ERROR [{host.name}]: script fallback failed: {exc}",
                        level="error",
                    )

            merged = merge_scap_and_script_results(
                db_rules=rules_payload,
                scap_outcomes=scap_outcomes,
                script_results=script_parsed,
                result_kind=result_kind,
            )
            if not merged and not scap_outcomes and not script_parsed:
                upsert_check_result(
                    host_db,
                    job_run_id=job_run_id,
                    host_id=host.id,
                    rule_tech_name="OSCAPI_ERROR",
                    status=CheckStatus.ERROR,
                    message="No OpenSCAP or script results produced",
                    raw_output=raw_oscap[:raw_limit] if raw_oscap else None,
                )
                host_db.commit()
                return 1, host_errors or [f"{host.name}: no SCAP results"]

            host_results = 0
            for item in merged:
                upsert_check_result(
                    host_db,
                    job_run_id=job_run_id,
                    host_id=host.id,
                    rule_tech_name=item["tech_name"],
                    status=_safe_status(item["status"]),
                    message=item["message"],
                    raw_output=(raw_oscap or "")[:raw_limit] or None,
                )
                host_results += 1

            host_db.commit()
            return host_results, host_errors

    host_results = run_hosts_parallel(
        hosts,
        settings.job_host_concurrency,
        process_host,
        should_cancel=lambda: _is_run_cancelled(db, job_run_id),
    )
    results_count = sum(count for count, _ in host_results)
    errors = [err for _, errs in host_results for err in errs]
    return results_count, errors


def _playbook_credentials(host: Host) -> dict | None:
    if not host.credential:
        return None

    cred = host.credential
    secret = _credential_secret(cred)
    credentials: dict[str, str] = {}
    if cred.username:
        credentials["username"] = cred.username

    if cred.credential_type == CredentialType.SSH_PASSWORD:
        credentials["password"] = secret
    elif cred.credential_type == CredentialType.SSH_KEY:
        credentials["private_key"] = secret
        key_passphrase = ssh_auth_from_credential(cred, secret, settings)[2]
        if key_passphrase:
            credentials["key_passphrase"] = key_passphrase
    elif cred.credential_type == CredentialType.WINRM:
        credentials["password"] = secret

    return credentials or None


def _run_playbook_job(
    db: Session,
    job: Job,
    job_run: JobRun,
    hosts: list[Host],
    *,
    connection_mode: str = "auto",
) -> tuple[int, list[str]]:
    playbook = db.get(Playbook, job.playbook_id)
    if not playbook:
        raise ValueError("Playbook not found")

    publish_job_log(job_run.id, f"Running Ansible playbook: {playbook.name}")
    job_run_id = job_run.id
    playbook_content = upgrade_connectivity_check_content(playbook.content)
    raw_limit = _raw_output_limit()

    package_dir: Path | None = None
    if playbook.profile_id:
        profile = db.get(Profile, playbook.profile_id)
        if profile and profile.package_path:
            candidate = Path(profile.package_path)
            if candidate.is_dir():
                package_dir = candidate
    sidecar_files = load_playbook_sidecar_files(playbook_content, package_dir)
    if sidecar_files:
        publish_job_log(
            job_run.id,
            f"Attached package scripts for Ansible script module: {', '.join(sorted(sidecar_files))}",
        )
    else:
        missing_refs = extract_script_module_refs(playbook_content)
        if missing_refs:
            publish_job_log(
                job_run.id,
                "WARNING: playbook references script module file(s) "
                f"{', '.join(missing_refs)} but they were not found under the profile package",
                level="warning",
            )

    def process_host(host: Host) -> tuple[int, list[str]]:
        with SessionLocal() as host_db:
            if _is_run_cancelled(host_db, job_run_id):
                raise InterruptedError("Job run cancelled")

            if not host.credential:
                message = f"Host '{host.name}' has no credential assigned"
                publish_job_log(job_run_id, f"ERROR [{host.name}]: {message}", level="error")
                upsert_check_result(
                    host_db,
                    job_run_id=job_run_id,
                    host_id=host.id,
                    rule_tech_name="PLAYBOOK_ERROR",
                    status=CheckStatus.ERROR,
                    message=message,
                    raw_output=message,
                )
                host_db.commit()
                return 1, [f"{host.name}: {message}"]

            publish_job_log(
                job_run_id,
                f"[{host.name}] Starting playbook (connection_mode={connection_mode})",
            )
            inventory = [_host_inventory_entry(host)]
            credentials = _playbook_credentials(host)

            try:
                output = run_playbook(
                    playbook_content,
                    inventory,
                    credentials=credentials,
                    connection_mode=connection_mode,  # type: ignore[arg-type]
                    sidecar_files=sidecar_files,
                )
                publish_job_log(job_run_id, f"[{host.name}] Playbook finished successfully")
                results_written = _persist_playbook_host_results(
                    host_db,
                    job_run_id=job_run_id,
                    host_id=host.id,
                    output=output,
                    raw_limit=raw_limit,
                    ok=True,
                )
                host_db.commit()
                return results_written, []
            except InterruptedError:
                raise
            except Exception as exc:
                reraise_if_transient(exc)
                message = str(exc).strip() or "Playbook execution failed"
                output = message
                if isinstance(exc, AnsiblePlaybookError) and exc.output:
                    output = f"{message}\n{exc.output}".strip()
                publish_job_log(job_run_id, f"ERROR [{host.name}]: {message}", level="error")
                results_written = _persist_playbook_host_results(
                    host_db,
                    job_run_id=job_run_id,
                    host_id=host.id,
                    output=output,
                    raw_limit=raw_limit,
                    ok=False,
                    error_message=message.split("\n", 1)[0][:500],
                )
                host_db.commit()
                return results_written, [f"{host.name}: {message.split(chr(10), 1)[0]}"]

    host_results = run_hosts_parallel(
        hosts,
        settings.job_host_concurrency,
        process_host,
        should_cancel=lambda: _is_run_cancelled(db, job_run_id),
    )
    results_count = sum(count for count, _ in host_results)
    errors = [err for _, errs in host_results for err in errs]
    return results_count, errors


def _run_profile_job(
    db: Session,
    job: Job,
    job_run: JobRun,
    profile: Profile,
    hosts: list[Host],
) -> tuple[int, list[str]]:
    package_dir = Path(profile.package_path) if profile.package_path else Path(settings.profiles_path)

    if profile.source_format == "xccdf":
        benchmark_path = resolve_scap_benchmark_path(package_dir)
        if benchmark_path is not None:
            publish_job_log(
                job_run.id,
                f"Using OpenSCAP executor for XCCDF profile '{profile.profile_name}'",
            )
            return _run_scap_profile_job(
                db, job, job_run, profile, hosts, package_dir, benchmark_path, mode="xccdf"
            )

    if profile.source_format == "oval":
        oval_path = resolve_oval_path(package_dir)
        if oval_path is not None:
            publish_job_log(
                job_run.id,
                f"Using OpenSCAP OVAL evaluator for profile '{profile.profile_name}'",
            )
            return _run_scap_profile_job(
                db, job, job_run, profile, hosts, package_dir, oval_path, mode="oval"
            )

    scripts = db.execute(
        select(CheckScript).where(
            CheckScript.profile_id == profile.id,
            CheckScript.script_kind == ScriptKind.AUDIT,
        )
    ).scalars().all()
    if job.execution_type is not None:
        filtered = [script for script in scripts if script.execution_type == job.execution_type]
        if filtered:
            scripts = filtered
        elif scripts:
            # Legacy network jobs forced ANSIBLE while package scripts are PYTHON.
            publish_job_log(
                job_run.id,
                (
                    f"No {job.execution_type.value} audit scripts for profile "
                    f"'{profile.profile_name}'; using available scripts"
                ),
                level="warning",
            )
    package_dir = Path(profile.package_path) if profile.package_path else Path(settings.profiles_path)
    job_run_id = job_run.id
    raw_limit = _raw_output_limit()

    def process_host(host: Host) -> tuple[int, list[str]]:
        with SessionLocal() as host_db:
            if _is_run_cancelled(host_db, job_run_id):
                raise InterruptedError("Job run cancelled")

            host_results = 0
            host_errors: list[str] = []
            config_env = (
                _network_script_extra_env(host_db, job, host)
                if job.scope == JobScope.NETWORK
                else {}
            )
            config_path = Path(config_env["SECAUDIT_CONFIG_FILE"]) if config_env.get("SECAUDIT_CONFIG_FILE") else None
            try:
                service_env = _service_env_for_profile(host, profile)
            except ValueError as exc:
                message = str(exc)
                publish_job_log(job_run_id, f"ERROR [{host.name}]: {message}", level="error")
                upsert_check_result(
                    host_db,
                    job_run_id=job_run_id,
                    host_id=host.id,
                    rule_tech_name="EXEC_ERROR",
                    status=CheckStatus.ERROR,
                    message=message,
                )
                host_db.commit()
                return 1, [f"{host.name}: {message}"]
            merged_env = _merge_extra_env(config_env, service_env)
            try:
                for script in scripts:
                    if _is_run_cancelled(host_db, job_run_id):
                        raise InterruptedError("Job run cancelled")
                    script_path = resolve_script_under_package(package_dir, script.script_file)
                    rules = _load_interpreter_rules(host_db, script)

                    try:
                        output = _execute_check(
                            host,
                            script_path,
                            script.execution_type,
                            job_run_id,
                            extra_env=merged_env,
                        )
                    except InterruptedError:
                        raise
                    except Exception as exc:
                        reraise_if_transient(exc)
                        host_errors.append(f"{host.name}: {exc}")
                        publish_job_log(job_run_id, f"ERROR [{host.name}]: {exc}", level="error")
                        upsert_check_result(
                            host_db,
                            job_run_id=job_run_id,
                            host_id=host.id,
                            rule_tech_name="EXEC_ERROR",
                            status=CheckStatus.ERROR,
                            message=str(exc),
                        )
                        host_results += 1
                        continue

                    parsed = apply_interpreter_rules(output, rules)
                    if not parsed:
                        upsert_check_result(
                            host_db,
                            job_run_id=job_run_id,
                            host_id=host.id,
                            rule_tech_name="PARSE_ERROR",
                            status=CheckStatus.ERROR,
                            message="No check results parsed from script output",
                            raw_output=output[:raw_limit],
                        )
                        host_results += 1
                        continue

                    for item in parsed:
                        upsert_check_result(
                            host_db,
                            job_run_id=job_run_id,
                            host_id=host.id,
                            rule_tech_name=item["tech_name"],
                            status=_safe_status(item["status"]),
                            message=item["message"],
                            raw_output=output[:raw_limit],
                        )
                        host_results += 1

                host_db.commit()
                return host_results, host_errors
            finally:
                if config_path is not None:
                    try:
                        config_path.unlink(missing_ok=True)
                    except OSError:
                        pass

    host_results = run_hosts_parallel(
        hosts,
        settings.job_host_concurrency,
        process_host,
        should_cancel=lambda: _is_run_cancelled(db, job_run_id),
    )
    results_count = sum(count for count, _ in host_results)
    errors = [err for _, errs in host_results for err in errs]
    return results_count, errors


def _run_network_compliance_job(
    db: Session,
    job: Job,
    job_run: JobRun,
    hosts: list[Host],
) -> tuple[int, list[str]]:
    mode = job.network_check_mode or NetworkCheckMode.BOTH
    configs = db.execute(
        select(NetworkDeviceConfig).where(NetworkDeviceConfig.job_id == job.id)
    ).scalars().all()
    results_count = 0
    errors: list[str] = []

    for host in hosts:
        if _is_run_cancelled(db, job_run.id):
            break
        host_configs = [c for c in configs if c.host_id in (None, host.id)]
        config_text: str | None = None
        vendor: NetworkVendor = NetworkVendor.GENERIC

        if mode in {NetworkCheckMode.CONFIG_UPLOAD, NetworkCheckMode.BOTH} and host_configs:
            latest = host_configs[0]
            config_text = latest.content
            vendor = latest.vendor
            publish_job_log(job_run.id, f"Parsing uploaded config for {host.name} ({latest.filename})")

        if config_text is None and mode in {NetworkCheckMode.REMOTE, NetworkCheckMode.BOTH}:
            if not host.credential:
                errors.append(f"{host.name}: no credential for remote check")
                continue
            cred = host.credential
            secret = _credential_secret(cred)
            username = cred.username or "admin"
            password = secret if cred.credential_type == CredentialType.SSH_PASSWORD else None
            if not password:
                errors.append(f"{host.name}: remote network check requires ssh_password credential")
                continue
            try:
                vendor = NetworkVendor.GENERIC
                if host_configs:
                    vendor = host_configs[0].vendor
                config_text = fetch_running_config(
                    hostname=host.hostname.strip(),
                    port=host.port,
                    username=username,
                    password=password,
                    vendor=vendor,
                )
                publish_job_log(job_run.id, f"Fetched running-config from {host.name} via Netmiko")
            except Exception as exc:
                reraise_if_transient(exc)
                errors.append(f"{host.name}: remote fetch failed: {exc}")
                continue

        if not config_text:
            errors.append(f"{host.name}: no configuration available (upload config or enable remote mode)")
            continue

        parsed = parse_network_config(config_text, vendor)
        for check in parsed.checks:
            upsert_check_result(
                db,
                job_run_id=job_run.id,
                host_id=host.id,
                rule_tech_name=check.rule_tech_name,
                status=check.status,
                message=check.message,
                raw_output=config_text[:2000],
            )
            results_count += 1

    db.commit()
    return results_count, errors


@celery_app.task(name="app.tasks.compliance.heartbeat")
def heartbeat() -> str:
    touch_worker_heartbeat(settings.redis_url, ttl_seconds=settings.worker_heartbeat_max_age_seconds)
    return "ok"


@celery_app.task(
    bind=True,
    name="app.tasks.run_compliance_job",
    **TASK_RETRY_KWARGS,
)
def run_compliance_job(self, job_run_id: int, connection_mode: str = "auto", **_kwargs) -> dict:
    set_current_span_attributes(
        {
            "secaudit.job_run_id": job_run_id,
            "secaudit.connection_mode": connection_mode,
        }
    )
    job_run = None
    for attempt in range(5):
        with SessionLocal() as db:
            job_run = db.get(JobRun, job_run_id)
        if job_run:
            break
        if attempt < 4:
            time.sleep(0.2)

    if not job_run:
        with SessionLocal() as db:
            stale = db.get(JobRun, job_run_id)
            if stale:
                if stale.status == JobStatus.PENDING:
                    claim_pending_run(db, JobRun, job_run_id)
                transition_running_run(
                    db,
                    JobRun,
                    job_run_id,
                    JobStatus.FAILED,
                    error_message="Worker could not load job run record",
                )
        return {"error": "job_run not found"}

    with SessionLocal() as db:
        if not claim_pending_run(db, JobRun, job_run_id):
            status = current_run_status(db, JobRun, job_run_id)
            return {
                "job_run_id": job_run_id,
                "status": status.value if status else "not_found",
                "claimed": False,
            }
        job_run = db.get(JobRun, job_run_id)
        if not job_run:
            return {"error": "job_run not found"}

        job = db.get(Job, job_run.job_id)
        if not job:
            transition_running_run(
                db, JobRun, job_run_id, JobStatus.FAILED, error_message="Job not found"
            )
            job_run = db.get(JobRun, job_run_id)
            emit_run_notification(
                settings,
                run_kind="job",
                run_id=job_run_id,
                job_id=job_run.job_id,
                job_name=f"Job #{job_run.job_id}",
                status=job_run.status,
                error_message=job_run.error_message,
                owner_sub=None,
            )
            return {"error": "job not found"}

        publish_job_log(job_run_id, f"Job run #{job_run_id} started")

        hosts = _resolve_hosts(db, job)
        if not hosts:
            publish_job_log(job_run_id, "No hosts available", level="error")
            transition_running_run(
                db,
                JobRun,
                job_run_id,
                JobStatus.FAILED,
                error_message="No active hosts assigned to job",
            )
            job_run = db.get(JobRun, job_run_id)
            emit_run_notification(
                settings,
                run_kind="job",
                run_id=job_run_id,
                job_id=job.id,
                job_name=job.name,
                status=job_run.status,
                error_message=job_run.error_message,
                owner_sub=job.owner_sub,
            )
            return {"error": "no hosts"}

        try:
            if job.scope == JobScope.NETWORK:
                if job.profile_id:
                    profile = db.get(Profile, job.profile_id)
                    if not profile:
                        raise ValueError("Profile not found")
                    # Network Platform packages run Python checks on the worker via
                    # Netmiko/Paramiko (resource_* env), same as Juniper ONLINE scripts.
                    results_count, errors = _run_profile_job(db, job, job_run, profile, hosts)
                else:
                    results_count, errors = _run_network_compliance_job(db, job, job_run, hosts)
            elif job.playbook_id:
                results_count, errors = _run_playbook_job(
                    db, job, job_run, hosts, connection_mode=connection_mode
                )
            elif job.profile_id:
                profile = db.get(Profile, job.profile_id)
                if not profile:
                    raise ValueError("Profile not found")
                results_count, errors = _run_profile_job(db, job, job_run, profile, hosts)
            else:
                raise ValueError("Job has no profile_id or playbook_id")

            if _is_run_cancelled(db, job_run_id):
                publish_job_log(job_run_id, "Job run cancelled")
                db.commit()
                return {"job_run_id": job_run_id, "status": JobStatus.CANCELLED.value}

            error_results = db.execute(
                select(CheckResult.id).where(
                    CheckResult.job_run_id == job_run.id,
                    CheckResult.status == CheckStatus.ERROR,
                ).limit(1)
            ).scalar_one_or_none()
            has_check_errors = error_results is not None or bool(errors)

            if results_count == 0:
                final_status = JobStatus.FAILED
                final_error = "; ".join(errors) or "No results produced"
            elif has_check_errors:
                final_status = JobStatus.FAILED
                final_error = (
                    "; ".join(errors)[:2000]
                    if errors
                    else "One or more checks failed with errors"
                )
            else:
                final_status = JobStatus.COMPLETED
                final_error = None

            transition_running_run(
                db,
                JobRun,
                job_run_id,
                final_status,
                error_message=final_error,
            )
            job_run = db.get(JobRun, job_run_id)
            publish_job_log(job_run_id, f"Job run finished: {job_run.status.value}")
            emit_run_notification(
                settings,
                run_kind="job",
                run_id=job_run_id,
                job_id=job.id,
                job_name=job.name,
                status=job_run.status,
                error_message=job_run.error_message,
                owner_sub=job.owner_sub,
            )
            return {"job_run_id": job_run_id, "status": job_run.status.value}

        except InterruptedError:
            transition_running_run(db, JobRun, job_run_id, JobStatus.CANCELLED)
            publish_job_log(job_run_id, "Job run cancelled")
            return {"job_run_id": job_run_id, "status": JobStatus.CANCELLED.value}

        except Exception as exc:
            # Let Celery autoretry see transient infra errors; do not convert to a
            # successful task return with FAILED status.
            reraise_if_transient(exc)
            publish_job_log(job_run_id, f"Job failed: {exc}", level="error")
            transition_running_run(
                db, JobRun, job_run_id, JobStatus.FAILED, error_message=str(exc)
            )
            job_run = db.get(JobRun, job_run_id)
            emit_run_notification(
                settings,
                run_kind="job",
                run_id=job_run_id,
                job_id=job.id,
                job_name=job.name,
                status=job_run.status,
                error_message=job_run.error_message,
                owner_sub=job.owner_sub,
            )
            return {"job_run_id": job_run_id, "status": "failed", "error": str(exc)}


@celery_app.task(name="app.tasks.compliance.run_scheduled_jobs")
def run_scheduled_jobs() -> dict:
    lock_key = "beat:schedule_lock:compliance"
    lock_client, lock_token = acquire_beat_lock(
        settings.redis_url,
        lock_key,
        ttl_seconds=settings.beat_lock_ttl_seconds,
    )
    if lock_token is None:
        return {"skipped": True, "reason": "lock_not_acquired"}

    try:
        return _run_scheduled_jobs_locked()
    finally:
        release_beat_lock(lock_client, lock_key, lock_token)


def _run_scheduled_jobs_locked() -> dict:
    from croniter import croniter

    now = datetime.now(UTC)
    triggered: list[int] = []

    with SessionLocal() as db:
        jobs = db.execute(
            select(Job).where(
                Job.is_active.is_(True),
                Job.is_scheduled.is_(True),
                Job.cron_expression.isnot(None),
            )
        ).scalars().all()

        for job in jobs:
            try:
                cron = croniter(job.cron_expression, now)
                prev_run = cron.get_prev(datetime)
            except (ValueError, KeyError) as exc:
                logger.warning(
                    "Skipping scheduled compliance job id=%s: invalid cron %r: %s",
                    job.id,
                    job.cron_expression,
                    exc,
                )
                continue

            if job.last_scheduled_at and prev_run <= job.last_scheduled_at.replace(tzinfo=UTC):
                continue

            job_run = JobRun(job_id=job.id, status=JobStatus.PENDING)
            db.add(job_run)
            db.flush()
            enqueue_outbox_row(
                db,
                task_name="app.tasks.run_compliance_job",
                args=[job_run.id],
                queue="compliance",
                callback_kind="job_run",
                callback_ref_id=job_run.id,
                correlation={"source": "schedule", "run_kind": "job", "run_id": job_run.id},
            )

            job.last_scheduled_at = now
            triggered.append(job_run.id)

        db.commit()

    return {"triggered_runs": triggered, "count": len(triggered)}
