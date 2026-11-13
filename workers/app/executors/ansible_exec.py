import json
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Literal

from secaudit_core.playbook_security import assert_playbook_local_execution_policy
from secaudit_core.settings import SecAuditSettings
from secaudit_core.ssh_fingerprint import retarget_known_hosts_entry
from secaudit_core.tracing import start_span

logger = logging.getLogger(__name__)

ConnectionMode = Literal["auto", "ssh", "paramiko", "winrm"]


class AnsiblePlaybookError(RuntimeError):
    """Raised when ansible-runner fails; preserves collected host event output."""

    def __init__(self, message: str, *, output: str = "") -> None:
        super().__init__(message)
        self.output = output or ""


_EVENT_HOST = frozenset(
    {
        "runner_on_ok",
        "runner_on_failed",
        "runner_on_unreachable",
        "runner_on_skipped",
    }
)

# ansible.builtin.script / script: relative file beside the playbook
_SCRIPT_MODULE_REF_RE = re.compile(
    r"^\s*(?:-\s+)?(?:ansible\.builtin\.)?script:\s*(?:['\"]([^'\"]+)['\"]|(\S+))\s*$",
    re.MULTILINE,
)


def extract_script_module_refs(playbook_content: str) -> list[str]:
    """Return unique script filenames referenced by Ansible script modules."""
    refs: list[str] = []
    seen: set[str] = set()
    for quoted, bare in _SCRIPT_MODULE_REF_RE.findall(playbook_content or ""):
        raw = (quoted or bare or "").strip()
        if not raw:
            continue
        name = Path(raw).name
        if name in seen:
            continue
        seen.add(name)
        refs.append(name)
    return refs


def load_playbook_sidecar_files(
    playbook_content: str,
    package_dir: Path | None,
) -> dict[str, bytes]:
    """Load package files needed by script: tasks into a sidecar map."""
    if package_dir is None or not package_dir.is_dir():
        return {}
    files: dict[str, bytes] = {}
    for name in extract_script_module_refs(playbook_content):
        candidate = package_dir / name
        if candidate.is_file():
            files[name] = candidate.read_bytes()
    return files


def sshpass_available() -> bool:
    return shutil.which("sshpass") is not None


def resolve_connection_mode(
    inventory_host: dict,
    credentials: dict | None,
    connection_mode: ConnectionMode,
) -> ConnectionMode:
    if connection_mode != "auto":
        return connection_mode

    ansible_vars = inventory_host.get("ansible_vars") or {}
    if ansible_vars.get("ansible_connection") == "winrm" or credentials and credentials.get("winrm"):
        return "winrm"
    # Key auth: use paramiko (library SSH, same family as Operations asyncssh).
    # OpenSSH + ControlMaster=no opens many TCP sessions; flaky hosts then return
    # "Connection refused" while a single asyncssh Operations run still succeeds.
    if credentials and credentials.get("private_key"):
        return "paramiko"
    if credentials and credentials.get("password"):
        return "paramiko" if not sshpass_available() else "ssh"
    return "paramiko"


def _apply_connection_settings(
    host_vars: dict,
    credentials: dict | None,
    connection_mode: ConnectionMode,
    key_file: Path | None,
    *,
    winrm_cert_validation: str | None = None,
) -> None:
    # Read-only marker for templates; ansible_connection itself is policy-forbidden in content.
    host_vars["secaudit_connection"] = connection_mode
    if connection_mode == "winrm":
        from app.executors.winrm_exec import normalize_winrm_port, winrm_use_ssl

        host_vars["ansible_connection"] = "winrm"
        host_vars.setdefault("ansible_winrm_transport", "ntlm")
        validation = winrm_cert_validation
        if validation is None:
            from secaudit_core.settings import SecAuditSettings

            validation = SecAuditSettings().winrm_server_cert_validation_effective
        host_vars.setdefault("ansible_winrm_server_cert_validation", validation)
        # Inventory/discovery often stores SMB (445) or RDP (3389). Ansible's winrm
        # plugin defaults scheme to https when port != 5985, which breaks those hosts.
        winrm_port = normalize_winrm_port(host_vars.get("ansible_port"))
        host_vars["ansible_port"] = winrm_port
        host_vars["ansible_winrm_scheme"] = "https" if winrm_use_ssl(winrm_port) else "http"
        host_vars["ansible_winrm_port"] = winrm_port
        if credentials and credentials.get("password"):
            host_vars["ansible_password"] = credentials["password"]
        return

    if connection_mode == "paramiko":
        host_vars["ansible_connection"] = "paramiko"
        if credentials and credentials.get("password"):
            host_vars["ansible_password"] = credentials["password"]
        if key_file is not None:
            host_vars["ansible_ssh_private_key_file"] = str(key_file)
        return

    host_vars["ansible_connection"] = "ssh"
    if credentials and credentials.get("password"):
        host_vars["ansible_password"] = credentials["password"]
    if key_file is not None:
        host_vars["ansible_ssh_private_key_file"] = str(key_file)


def _extract_event_message(event: dict) -> tuple[str, str, str]:
    data = event.get("event_data", {})
    host = str(data.get("host") or "?")
    res = data.get("res") or {}
    task = str(data.get("task") or res.get("task") or "task")
    msg = res.get("msg") or res.get("stderr") or res.get("stdout") or res.get("module_stdout") or ""
    if isinstance(msg, (dict, list)):
        msg = json.dumps(msg, ensure_ascii=False)
    return host, task, str(msg).strip()


def _redact_values(text: str, values: list[str] | None) -> str:
    for value in values or []:
        if value and len(value) >= 4:
            text = text.replace(str(value), "***")
    return text


def _collect_runner_output(
    runner,
    *,
    check_mode: bool = False,
    redact_values: list[str] | None = None,
) -> tuple[str, list[str]]:
    lines: list[str] = []
    errors: list[str] = []

    for event in runner.events:
        event_type = event.get("event")
        if event_type not in _EVENT_HOST:
            continue
        host, task, msg = _extract_event_message(event)
        msg = _redact_values(msg, redact_values)
        prefix = f"[{host}] {task}"
        res = (event.get("event_data") or {}).get("res") or {}
        changed = bool(res.get("changed"))
        if event_type == "runner_on_ok":
            label = "WOULD CHANGE" if check_mode and changed else "OK"
            if msg:
                lines.append(f"{label} {prefix}: {msg}")
            else:
                lines.append(f"{label} {prefix}")
            continue
        if event_type == "runner_on_skipped":
            detail = f": {msg}" if msg else ""
            lines.append(f"SKIP {prefix}{detail}")
            continue

        detail = msg or "Task failed without details"
        line = f"FAILED {prefix}: {detail}"
        lines.append(line)
        errors.append(line)

    stdout = ""
    if runner.stdout:
        stdout = runner.stdout.read() if hasattr(runner.stdout, "read") else str(runner.stdout)
        stdout = _redact_values(stdout.strip(), redact_values)
        if stdout:
            lines.append(stdout)

    combined = "\n".join(line for line in lines if line)
    return combined, errors


def _failure_message(runner, errors: list[str], output: str) -> str:
    if errors:
        return "\n".join(errors)
    if output.strip():
        return output.strip()
    if runner.rc is not None:
        return f"Ansible playbook failed with exit code {runner.rc}"
    return "Ansible playbook failed"


_SHARED_COLLECTIONS_PATH = "/usr/share/ansible/collections"


def _ansible_collections_envvars() -> dict[str, str]:
    collections = Path(_SHARED_COLLECTIONS_PATH)
    if collections.is_dir():
        path = str(collections)
        return {
            "ANSIBLE_COLLECTIONS_PATH": path,
            "ANSIBLE_COLLECTIONS_PATHS": path,
        }
    return {}


def _ansible_local_envvars(work_dir: Path) -> dict[str, str]:
    """Overrides for ansible-runner when the process HOME is /nonexistent (Docker worker user)."""
    ssh_dir = work_dir / ".ssh"
    ssh_dir.mkdir(parents=True, exist_ok=True)
    local_tmp = work_dir / "ansible-local"
    local_tmp.mkdir(parents=True, exist_ok=True)
    try:
        ssh_dir.chmod(0o700)
    except OSError:
        pass
    return {
        "HOME": str(work_dir),
        "ANSIBLE_LOCAL_TMP": str(local_tmp),
        **_ansible_collections_envvars(),
    }


# ansible-runner seeds its env from os.environ. Only these variables may cross
# into the child; platform secrets (SECRET_KEY, DB/Redis passwords, Vault token)
# must never be visible to a playbook.
_ANSIBLE_CHILD_ENV_ALLOWLIST = frozenset(
    {
        "PATH",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LC_MESSAGES",
        "TZ",
        "TMPDIR",
        "TEMP",
        "TMP",
        "PYTHONPATH",
        "PYTHONIOENCODING",
        "PYTHONUTF8",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "WINDIR",
        "COMSPEC",
    }
)


def _ansible_child_env() -> dict[str, str]:
    """Environment for the isolated ansible-runner child process."""
    return {key: value for key, value in os.environ.items() if key in _ANSIBLE_CHILD_ENV_ALLOWLIST}


def _terminate_ansible_process(process: subprocess.Popen) -> None:
    """Kill ansible-child process group (playbook + stuck ssh)."""
    if process.poll() is not None:
        return
    try:
        if process.pid:
            os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def _run_ansible_child(
    run_kwargs: dict,
    cancel_event,
    work_dir: Path,
    *,
    timeout_seconds: int | None = None,
):
    """Execute ansible-runner in a subprocess that has no platform secrets."""
    settings = SecAuditSettings()
    timeout = max(
        30,
        int(
            timeout_seconds
            if timeout_seconds is not None
            else settings.ansible_playbook_timeout_seconds
        ),
    )
    result_path = work_dir / "runner-result.json"
    cancel_path = work_dir / "runner-cancel"
    payload = {
        "run_kwargs": run_kwargs,
        "result_path": str(result_path),
        "cancel_path": str(cancel_path),
    }
    from app.cancel_context import get_active_run
    from secaudit_core.run_cancel import register_run_child_pid, unregister_run_child_pid

    # New session so hung ssh grandchildren die with killpg on timeout/cancel.
    process = subprocess.Popen(
        [sys.executable, "-m", "app.executors.ansible_child"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_ansible_child_env(),
        cwd=str(Path(__file__).resolve().parents[2]),
        start_new_session=True,
    )
    active_run = get_active_run()
    if active_run is not None and process.pid:
        try:
            register_run_child_pid(
                settings.redis_url, active_run[0], active_run[1], process.pid
            )
        except Exception:
            logger.warning("Failed to register ansible child pid for cancel", exc_info=True)

    def _cancel_requested() -> bool:
        if cancel_event is not None and cancel_event.is_set():
            return True
        if active_run is None:
            return False
        try:
            from secaudit_core.run_cancel import is_run_cancel_requested

            return is_run_cancel_requested(
                settings.redis_url, active_run[0], active_run[1]
            )
        except Exception:
            return False

    def _watch_cancel() -> None:
        from secaudit_core.run_cancel import kill_run_child_pids

        while process.poll() is None:
            if not _cancel_requested():
                time.sleep(0.25)
                continue
            if cancel_event is not None:
                cancel_event.set()
            try:
                cancel_path.touch()
            except OSError:
                pass
            # Stuck OpenSSH ignores ansible-runner cancel_callback — kill now.
            _terminate_ansible_process(process)
            if active_run is not None:
                try:
                    kill_run_child_pids(
                        settings.redis_url, active_run[0], active_run[1]
                    )
                except Exception:
                    pass
            return

    # Always watch: Redis cancel flag is set by API in a different PID namespace.
    threading.Thread(target=_watch_cancel, daemon=True).start()

    try:
        try:
            stdout, stderr = process.communicate(
                json.dumps(payload, default=str),
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            _terminate_ansible_process(process)
            try:
                process.communicate(timeout=5)
            except (subprocess.TimeoutExpired, OSError):
                pass
            if _cancel_requested():
                raise InterruptedError("Job run cancelled") from exc
            raise AnsiblePlaybookError(
                f"Ansible playbook timed out after {timeout}s (hung SSH/session killed)"
            ) from exc

        # Redis/API cancel kills the child first; do not surface that as playbook ERROR.
        if _cancel_requested():
            _terminate_ansible_process(process)
            raise InterruptedError("Job run cancelled")
        if process.returncode != 0:
            detail = (stderr or stdout or "ansible-runner child failed").strip()
            raise AnsiblePlaybookError(f"Ansible runner failed: {detail[-1000:]}")
        if not result_path.is_file():
            raise AnsiblePlaybookError("Ansible runner produced no result")
        result = json.loads(result_path.read_text(encoding="utf-8"))
        if result.get("error"):
            raise AnsiblePlaybookError(str(result["error"]))
        return SimpleNamespace(
            status=result.get("status"),
            rc=result.get("rc"),
            stats=result.get("stats") or {},
            events=result.get("events") or [],
            stdout=result.get("stdout") or "",
        )
    finally:
        if active_run is not None and process.pid:
            try:
                unregister_run_child_pid(
                    settings.redis_url, active_run[0], active_run[1], process.pid
                )
            except Exception:
                pass


def normalize_private_key(raw: str) -> str:
    """Normalize PEM/OpenSSH key text so OpenSSL can load the temp file."""
    text = str(raw).replace("\r\n", "\n").replace("\r", "\n").strip()
    if text and not text.endswith("\n"):
        text += "\n"
    return text


def write_private_key_file(path: Path, raw: str, passphrase: str | None = None) -> None:
    """Write a temp private key. Encrypted keys are unlocked so OpenSSH never prompts/hangs."""
    text = normalize_private_key(raw)
    if not passphrase:
        path.write_text(text, encoding="utf-8")
        path.chmod(0o600)
        return

    # OpenSSH ignores ansible_ssh_private_key_passphrase and blocks on /dev/tty.
    # Unlock once with paramiko (same stack netmiko uses) and hand ssh an open key.
    from io import StringIO

    import paramiko

    key = None
    last_error: Exception | None = None
    for loader in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey):
        try:
            key = loader.from_private_key(StringIO(text), password=passphrase)
            break
        except Exception as exc:  # noqa: BLE001 - try next key type
            last_error = exc
    if key is None:
        raise ValueError(
            "Unable to decrypt SSH private key with the provided passphrase"
        ) from last_error
    key.write_private_key_file(str(path))
    path.chmod(0o600)


def ssh_client_args(*, known_hosts_file: Path, strict: bool) -> str:
    """Force OpenSSH off /etc/passwd HOME=/nonexistent (worker image).

    Do not set ConnectTimeout here: ansible_ssh_common_args are appended after
    ANSIBLE_TIMEOUT's ConnectTimeout and would override it (was 10s vs 120s),
    so playbook runs failed while Operations asyncssh still reached the host.
    """
    checking = "yes" if strict else "no"
    # Multiplex under the per-run HOME/.ssh (created by _ansible_local_envvars).
    control_path = known_hosts_file.parent / ".ssh" / "cm-%r@%h:%p"
    return (
        f"-o StrictHostKeyChecking={checking} "
        "-o GlobalKnownHostsFile=/dev/null "
        "-o ControlMaster=auto "
        "-o ControlPersist=120 "
        f"-o ControlPath={control_path} "
        "-o IdentitiesOnly=yes "
        "-o GSSAPIAuthentication=no "
        "-o GSSAPIKeyExchange=no "
        "-o ServerAliveInterval=15 "
        "-o ServerAliveCountMax=4 "
        f"-o UserKnownHostsFile={known_hosts_file}"
    )


def _apply_ssh_client_args(host_vars: dict, ssh_args: str) -> None:
    existing = str(host_vars.get("ansible_ssh_common_args") or "").strip()
    host_vars["ansible_ssh_common_args"] = f"{existing} {ssh_args}".strip() if existing else ssh_args


def run_playbook(
    playbook_content: str,
    inventory_hosts: list[dict],
    extravars: dict | None = None,
    credentials: dict | None = None,
    connection_mode: ConnectionMode = "auto",
    cancel_event=None,
    sidecar_files: dict[str, str | bytes] | None = None,
    check_mode: bool = False,
    tags: list[str] | None = None,
) -> str:
    """Run Ansible playbook via ansible-runner. Returns combined stdout events.

    sidecar_files: optional files written next to playbook.yml (e.g. script module sources).
    check_mode: pass ansible-playbook --check --diff (report changes, do not apply).
    tags: optional ansible-playbook --tags list (rule_tech_name for scoped remediation).
    """
    span_attrs = {
        "secaudit.executor": "ansible",
        "secaudit.hosts": len(inventory_hosts),
        "secaudit.connection_mode": connection_mode,
        "secaudit.sidecar_files": len(sidecar_files or {}),
        "secaudit.check_mode": check_mode,
        "secaudit.tags": len(tags or []),
    }
    with start_span("executor.ansible", attributes=span_attrs, kind="client"):
        return _run_playbook(
            playbook_content,
            inventory_hosts,
            extravars,
            credentials,
            connection_mode,
            cancel_event=cancel_event,
            sidecar_files=sidecar_files,
            check_mode=check_mode,
            tags=tags,
        )


def _run_playbook(
    playbook_content: str,
    inventory_hosts: list[dict],
    extravars: dict | None,
    credentials: dict | None,
    connection_mode: ConnectionMode,
    cancel_event=None,
    sidecar_files: dict[str, str | bytes] | None = None,
    *,
    check_mode: bool = False,
    tags: list[str] | None = None,
) -> str:
    from app.cancel_context import get_cancel_event, raise_if_cancelled

    cancel_event = cancel_event if cancel_event is not None else get_cancel_event()
    raise_if_cancelled()

    # Defense in depth: same local-execution policy as API validate.
    assert_playbook_local_execution_policy(playbook_content)

    settings = SecAuditSettings()
    with tempfile.TemporaryDirectory(prefix="secaudit_ansible_") as tmp:
        tmp_path = Path(tmp)
        playbook_file = tmp_path / "playbook.yml"
        playbook_file.write_text(playbook_content, encoding="utf-8")

        for relative_name, payload in (sidecar_files or {}).items():
            safe_name = Path(str(relative_name)).name
            if not safe_name or safe_name in {".", ".."}:
                continue
            target = tmp_path / safe_name
            if isinstance(payload, bytes):
                target.write_bytes(payload)
            else:
                target.write_text(str(payload), encoding="utf-8", newline="\n")
            # Audit scripts must be executable for ansible.builtin.script on some setups.
            try:
                target.chmod(0o755)
            except OSError:
                pass

        key_file: Path | None = None
        if credentials and credentials.get("private_key"):
            key_file = tmp_path / "id_rsa"
            write_private_key_file(
                key_file,
                str(credentials["private_key"]),
                credentials.get("key_passphrase"),
            )

        inventory = {"all": {"hosts": {}}}
        resolved_modes: list[str] = []
        known_host_entries: list[str] = []
        known_hosts_file = tmp_path / "known_hosts"
        known_hosts_file.write_text("", encoding="utf-8")
        try:
            known_hosts_file.chmod(0o600)
        except OSError:
            pass
        ssh_args = ssh_client_args(
            known_hosts_file=known_hosts_file,
            strict=settings.ssh_strict_host_key_checking_effective,
        )
        configured_known_hosts = (
            Path(settings.ssh_known_hosts_path)
            if settings.ssh_known_hosts_path
            else None
        )
        if configured_known_hosts:
            try:
                known_host_entries.extend(
                    line
                    for line in configured_known_hosts.read_text(encoding="utf-8").splitlines()
                    if line.strip() and not line.lstrip().startswith("#")
                )
            except OSError as exc:
                if settings.ssh_strict_host_key_checking_effective:
                    raise RuntimeError("Configured SSH known_hosts file is unreadable") from exc

        for host in inventory_hosts:
            name = host["name"].strip()
            host_vars = {
                "ansible_host": host["hostname"].strip(),
                "ansible_port": host.get("port", 22),
                **(host.get("ansible_vars") or {}),
            }
            if credentials and credentials.get("username"):
                host_vars["ansible_user"] = credentials["username"]
            if str(host_vars.get("ansible_connection") or "").strip().lower() == "local":
                raise ValueError(
                    f"Host '{name}': ansible_connection=local is not allowed in inventory"
                )

            mode = resolve_connection_mode(host, credentials, connection_mode)
            resolved_modes.append(f"{name}={mode}")
            entry = retarget_known_hosts_entry(
                str(host.get("ssh_known_hosts_entry") or "").strip() or None,
                host_vars["ansible_host"],
            )
            if entry:
                known_host_entries.append(entry)
            elif (
                mode in {"ssh", "paramiko"}
                and settings.ssh_strict_host_key_checking_effective
                and configured_known_hosts is None
            ):
                raise ValueError(
                    f"Host '{name}' has no stored SSH host key; scan its fingerprint before execution"
                )
            _apply_connection_settings(host_vars, credentials, mode, key_file)
            if mode == "ssh":
                _apply_ssh_client_args(host_vars, ssh_args)
            inventory["all"]["hosts"][name] = host_vars

        try:
            tmp_path.chmod(0o700)
        except OSError:
            pass
        inv_file = tmp_path / "inventory.json"
        inv_file.write_text(json.dumps(inventory), encoding="utf-8")
        try:
            inv_file.chmod(0o600)
        except OSError:
            pass

        playbook_timeout = max(30, int(settings.ansible_playbook_timeout_seconds))
        envvars: dict[str, str] = {
            **_ansible_local_envvars(tmp_path),
            "ANSIBLE_RETRY_FILES_ENABLED": "False",
            "ANSIBLE_REMOTE_TMP": "/tmp/.ansible/tmp",
            # Connection/plugin default; wall-clock kill in _run_ansible_child is authoritative.
            "ANSIBLE_TIMEOUT": str(min(120, playbook_timeout)),
            # Fewer TCP handshakes per task (closer to one Operations asyncssh session).
            "ANSIBLE_SSH_PIPELINING": "True",
        }
        if not settings.ssh_strict_host_key_checking_effective:
            envvars["ANSIBLE_PARAMIKO_HOST_KEY_AUTO_ADD"] = "True"
        # Prefer sshpass env so inventory JSON is not the only secret carrier.
        if credentials and credentials.get("password") and sshpass_available():
            envvars["SSHPASS"] = str(credentials["password"])
        if settings.ssh_strict_host_key_checking_effective:
            known_hosts_file.write_text(
                "\n".join(dict.fromkeys(known_host_entries)) + "\n",
                encoding="utf-8",
            )
            envvars["ANSIBLE_HOST_KEY_CHECKING"] = "True"
        else:
            # Explicitly available only when the effective non-production policy disables trust checks.
            envvars["ANSIBLE_HOST_KEY_CHECKING"] = "False"
        # Always pin UserKnownHostsFile: OpenSSH uses passwd HOME (/nonexistent), not $HOME.
        envvars["ANSIBLE_SSH_ARGS"] = ssh_args
        if credentials and credentials.get("username"):
            envvars["ANSIBLE_REMOTE_USER"] = credentials["username"]

        try:
            run_kwargs: dict = {
                "private_data_dir": str(tmp_path),
                "playbook": str(playbook_file),
                "inventory": str(inv_file),
                "extravars": extravars or {},
                "envvars": envvars,
                "quiet": False,
                "ignore_logging": True,
            }
            cmdline_parts: list[str] = []
            if check_mode:
                cmdline_parts.append("--check --diff")
            clean_tags = [str(tag).strip() for tag in (tags or []) if str(tag).strip()]
            if clean_tags:
                cmdline_parts.append("--tags " + ",".join(clean_tags))
            if cmdline_parts:
                run_kwargs["cmdline"] = " ".join(cmdline_parts)
            runner = _run_ansible_child(
                run_kwargs,
                cancel_event,
                tmp_path,
                timeout_seconds=playbook_timeout,
            )
        finally:
            # Best-effort shred of secrets written for the run.
            try:
                if inv_file.exists():
                    inv_file.write_text("{}\n", encoding="utf-8")
            except OSError:
                pass
            envvars.pop("SSHPASS", None)

        if cancel_event and cancel_event.is_set():
            raise InterruptedError("Job run cancelled")

        redact_values = [
            str(credentials.get(key) or "")
            for key in ("password", "key_passphrase", "private_key")
        ] if credentials else []
        output, errors = _collect_runner_output(
            runner, check_mode=check_mode, redact_values=redact_values
        )

        if runner.status == "failed" or runner.rc not in (None, 0):
            modes = ", ".join(resolved_modes)
            detail = _failure_message(runner, errors, output)
            raise AnsiblePlaybookError(
                f"{detail}\n(connection: {modes})",
                output=output,
            )

        mode_note = "check mode, no changes applied; " if check_mode else ""
        header = f"Playbook completed ({mode_note}connection: {', '.join(resolved_modes)})"
        return f"{header}\n{output}".strip() if output else header
