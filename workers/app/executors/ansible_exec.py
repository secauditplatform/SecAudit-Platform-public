import json
import re
import shutil
import tempfile
from pathlib import Path
from typing import Literal

import ansible_runner
import yaml

from secaudit_core.playbook_policy import validate_playbook_policy, validate_playbook_text
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


def _collect_runner_output(runner: ansible_runner.Runner) -> tuple[str, list[str]]:
    lines: list[str] = []
    errors: list[str] = []

    for event in runner.events:
        event_type = event.get("event")
        if event_type not in _EVENT_HOST:
            continue
        host, task, msg = _extract_event_message(event)
        prefix = f"[{host}] {task}"
        if event_type == "runner_on_ok":
            if msg:
                lines.append(f"OK {prefix}: {msg}")
            else:
                lines.append(f"OK {prefix}")
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
        stdout = stdout.strip()
        if stdout:
            lines.append(stdout)

    combined = "\n".join(line for line in lines if line)
    return combined, errors


def _failure_message(runner: ansible_runner.Runner, errors: list[str], output: str) -> str:
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
    local_tmp = work_dir / "ansible-local"
    local_tmp.mkdir(parents=True, exist_ok=True)
    return {
        "HOME": str(work_dir),
        "ANSIBLE_LOCAL_TMP": str(local_tmp),
        **_ansible_collections_envvars(),
    }


def run_playbook(
    playbook_content: str,
    inventory_hosts: list[dict],
    extravars: dict | None = None,
    credentials: dict | None = None,
    connection_mode: ConnectionMode = "auto",
    cancel_event=None,
    sidecar_files: dict[str, str | bytes] | None = None,
) -> str:
    """Run Ansible playbook via ansible-runner. Returns combined stdout events.

    sidecar_files: optional files written next to playbook.yml (e.g. script module sources).
    """
    span_attrs = {
        "secaudit.executor": "ansible",
        "secaudit.hosts": len(inventory_hosts),
        "secaudit.connection_mode": connection_mode,
        "secaudit.sidecar_files": len(sidecar_files or {}),
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
        )


def _run_playbook(
    playbook_content: str,
    inventory_hosts: list[dict],
    extravars: dict | None,
    credentials: dict | None,
    connection_mode: ConnectionMode,
    cancel_event=None,
    sidecar_files: dict[str, str | bytes] | None = None,
) -> str:
    from app.cancel_context import get_cancel_event, raise_if_cancelled

    cancel_event = cancel_event if cancel_event is not None else get_cancel_event()
    raise_if_cancelled()

    try:
        validate_playbook_text(playbook_content)
        loaded = yaml.safe_load(playbook_content)
        validate_playbook_policy(loaded)
    except ValueError as exc:
        raise AnsiblePlaybookError(str(exc)) from exc
    except yaml.YAMLError as exc:
        raise AnsiblePlaybookError(f"Invalid playbook YAML: {exc}") from exc

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
            key_file.write_text(credentials["private_key"], encoding="utf-8")
            key_file.chmod(0o600)

        inventory = {"all": {"hosts": {}}}
        resolved_modes: list[str] = []
        known_host_entries: list[str] = []
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
            inventory["all"]["hosts"][name] = host_vars

        inv_file = tmp_path / "inventory.json"
        inv_file.write_text(json.dumps(inventory), encoding="utf-8")

        envvars: dict[str, str] = {
            **_ansible_local_envvars(tmp_path),
            "ANSIBLE_RETRY_FILES_ENABLED": "False",
            "ANSIBLE_REMOTE_TMP": "/tmp/.ansible/tmp",
        }
        if settings.ssh_strict_host_key_checking_effective:
            known_hosts_file = tmp_path / "known_hosts"
            known_hosts_file.write_text(
                "\n".join(dict.fromkeys(known_host_entries)) + "\n",
                encoding="utf-8",
            )
            known_hosts_file.chmod(0o600)
            envvars["ANSIBLE_HOST_KEY_CHECKING"] = "True"
            envvars["ANSIBLE_SSH_ARGS"] = (
                f"-o StrictHostKeyChecking=yes -o UserKnownHostsFile={known_hosts_file}"
            )
        else:
            # Explicitly available only when the effective non-production policy disables trust checks.
            envvars["ANSIBLE_HOST_KEY_CHECKING"] = "False"
        if credentials and credentials.get("username"):
            envvars["ANSIBLE_REMOTE_USER"] = credentials["username"]

        runner = ansible_runner.run(
            playbook=str(playbook_file),
            inventory=str(inv_file),
            extravars=extravars or {},
            envvars=envvars,
            quiet=False,
            ignore_logging=True,
            cancel_callback=(lambda: bool(cancel_event and cancel_event.is_set()))
            if cancel_event is not None
            else None,
        )

        if cancel_event and cancel_event.is_set():
            raise InterruptedError("Job run cancelled")

        output, errors = _collect_runner_output(runner)

        if runner.status == "failed" or runner.rc not in (None, 0):
            modes = ", ".join(resolved_modes)
            detail = _failure_message(runner, errors, output)
            raise AnsiblePlaybookError(
                f"{detail}\n(connection: {modes})",
                output=output,
            )

        header = f"Playbook completed (connection: {', '.join(resolved_modes)})"
        return f"{header}\n{output}".strip() if output else header
