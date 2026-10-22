import json
import os
import re
import shutil
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
from secaudit_core.tracing import start_span

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
    if credentials and credentials.get("private_key"):
        return "ssh"
    if credentials and credentials.get("password"):
        return "paramiko" if not sshpass_available() else "ssh"
    return "ssh"


def _apply_connection_settings(
    host_vars: dict,
    credentials: dict | None,
    connection_mode: ConnectionMode,
    key_file: Path | None,
    *,
    winrm_cert_validation: str | None = None,
) -> None:
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
            if credentials and credentials.get("key_passphrase"):
                host_vars["ansible_ssh_private_key_passphrase"] = credentials["key_passphrase"]
        return

    host_vars["ansible_connection"] = "ssh"
    if credentials and credentials.get("password"):
        host_vars["ansible_password"] = credentials["password"]
    if key_file is not None:
        host_vars["ansible_ssh_private_key_file"] = str(key_file)
        if credentials and credentials.get("key_passphrase"):
            host_vars["ansible_ssh_private_key_passphrase"] = credentials["key_passphrase"]


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


def _run_ansible_child(
    run_kwargs: dict,
    cancel_event,
    work_dir: Path,
):
    """Execute ansible-runner in a subprocess that has no platform secrets."""
    result_path = work_dir / "runner-result.json"
    cancel_path = work_dir / "runner-cancel"
    payload = {
        "run_kwargs": run_kwargs,
        "result_path": str(result_path),
        "cancel_path": str(cancel_path),
    }
    process = subprocess.Popen(
        [sys.executable, "-m", "app.executors.ansible_child"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=_ansible_child_env(),
        cwd=str(Path(__file__).resolve().parents[2]),
    )

    def _watch_cancel() -> None:
        while process.poll() is None:
            if cancel_event is not None and cancel_event.is_set():
                try:
                    cancel_path.touch()
                except OSError:
                    pass
                return
            time.sleep(0.25)

    if cancel_event is not None:
        threading.Thread(target=_watch_cancel, daemon=True).start()

    stdout, stderr = process.communicate(json.dumps(payload, default=str))
    if cancel_event is not None and cancel_event.is_set():
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


def normalize_private_key(raw: str) -> str:
    """Normalize PEM/OpenSSH key text so OpenSSL can load the temp file."""
    text = str(raw).replace("\r\n", "\n").replace("\r", "\n").strip()
    if text and not text.endswith("\n"):
        text += "\n"
    return text


def ssh_client_args(*, known_hosts_file: Path, strict: bool) -> str:
    """Force OpenSSH off /etc/passwd HOME=/nonexistent (worker image)."""
    checking = "yes" if strict else "no"
    return (
        f"-o StrictHostKeyChecking={checking} "
        "-o GlobalKnownHostsFile=/dev/null "
        "-o ControlMaster=no "
        "-o ControlPath=none "
        "-o IdentitiesOnly=yes "
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
) -> str:
    """Run Ansible playbook via ansible-runner. Returns combined stdout events.

    sidecar_files: optional files written next to playbook.yml (e.g. script module sources).
    check_mode: pass ansible-playbook --check --diff (report changes, do not apply).
    """
    span_attrs = {
        "secaudit.executor": "ansible",
        "secaudit.hosts": len(inventory_hosts),
        "secaudit.connection_mode": connection_mode,
        "secaudit.sidecar_files": len(sidecar_files or {}),
        "secaudit.check_mode": check_mode,
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
            key_file.write_text(normalize_private_key(str(credentials["private_key"])), encoding="utf-8")
            key_file.chmod(0o600)

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
            entry = str(host.get("ssh_known_hosts_entry") or "").strip()
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

        envvars: dict[str, str] = {
            **_ansible_local_envvars(tmp_path),
            "ANSIBLE_RETRY_FILES_ENABLED": "False",
            "ANSIBLE_REMOTE_TMP": "/tmp/.ansible/tmp",
        }
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
            if check_mode:
                run_kwargs["cmdline"] = "--check --diff"
            runner = _run_ansible_child(run_kwargs, cancel_event, tmp_path)
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
