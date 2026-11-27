"""Registry of script executors.

connect / run / cancel / collect_facts is the contract. Cancel stays inside the
transport via cancel_context; this registry does not open a second channel.
OpenSCAP fact collection stays in oscap_exec (it is not an ExecutionType).
AuditFlow stays in audit_flow_runner (nmap orchestration, not this contract).
"""

from __future__ import annotations

from typing import Any, Callable

from secaudit_core.models import ExecutionType

from app.celery_app import settings
from app.executors.ansible_exec import run_playbook
from app.executors.python_exec import (
    run_script_locally_with_resource_env,
    run_script_over_ssh as run_script_over_python,
)
from app.executors.ssh import run_package_script_over_ssh, run_script_over_ssh
from app.executors.winrm_exec import run_script_over_winrm
from app.logging_pub import publish_job_log


class ExecutorAdapter:
    def __init__(self, execution_type: ExecutionType, run: Callable[..., str]):
        self.execution_type = execution_type
        self._run = run

    def connect(self, host, **kwargs: Any) -> None:
        """Transport selection happens in run. Missing credentials raise there."""
        return None

    def run(self, host, **kwargs: Any) -> str:
        return self._run(host, **kwargs)

    def cancel(self, host, **kwargs: Any) -> None:
        # shortcut: ssh/winrm already watch cancel_context; no separate cancel RPC.
        return None

    def collect_facts(self, host, **kwargs: Any) -> str:
        return self.run(host, **kwargs)


def _audit_ssh(host, **ctx) -> str:
    from app.tasks.compliance import _become_kwargs, _iter_ssh_credentials

    attempts = list(_iter_ssh_credentials(host))
    if not attempts:
        raise ValueError("SSH requires ssh_password or ssh_key credential")
    last_error: Exception | None = None
    for attempt_cred, attempt_user, password, private_key, key_passphrase in attempts:
        become = _become_kwargs(attempt_cred)
        try:
            if ctx["use_package"]:
                return run_package_script_over_ssh(
                    hostname=host.hostname.strip(),
                    port=host.port,
                    username=attempt_user,
                    password=password,
                    private_key=private_key,
                    package_dir=ctx["package_dir"],
                    script_file=ctx["script_file"],
                    known_hosts_entry=ctx["known_hosts_entry"],
                    key_passphrase=key_passphrase,
                    extra_env=ctx["extra_env"],
                    script_content_override=ctx["script_override"],
                    **become,
                )
            return run_script_over_ssh(
                hostname=host.hostname.strip(),
                port=host.port,
                username=attempt_user,
                password=password,
                private_key=private_key,
                script_path=ctx["run_script_path"],
                known_hosts_entry=ctx["known_hosts_entry"],
                key_passphrase=key_passphrase,
                extra_env=ctx["extra_env"],
                **become,
            )
        except Exception as exc:
            last_error = exc
            publish_job_log(
                ctx["job_run_id"],
                f"[{host.name}] SSH auth failed with {attempt_cred.name}: {exc}",
                level="warning",
            )
    raise last_error or ValueError("SSH authentication failed for all linked credentials")


def _audit_winrm(host, **ctx) -> str:
    from secaudit_core.models import CredentialType

    from app.tasks.compliance import _credential_secret

    winrm_cred = next((item for item in ctx["creds"] if item.credential_type == CredentialType.WINRM), None)
    if not winrm_cred:
        raise ValueError("WinRM checks require winrm credential")
    return run_script_over_winrm(
        hostname=host.hostname.strip(),
        port=host.port,
        username=winrm_cred.username or "root",
        password=_credential_secret(winrm_cred),
        script_path=ctx["run_script_path"],
        server_cert_validation=settings.winrm_server_cert_validation_effective,
        extra_env=ctx["extra_env"],
    )


def _audit_python(host, **ctx) -> str:
    from secaudit_core.credential_auth import ssh_auth_from_credential
    from secaudit_core.models import CredentialType
    from secaudit_core.network_scope import host_is_network

    cred = ctx["cred"]
    secret = ctx["secret"]
    password = secret if cred and cred.credential_type == CredentialType.SSH_PASSWORD else None
    private_key = secret if cred and cred.credential_type == CredentialType.SSH_KEY else None
    key_passphrase = (
        ssh_auth_from_credential(cred, secret, settings)[2]
        if cred and cred.credential_type == CredentialType.SSH_KEY
        else None
    )
    if host_is_network(host):
        if not password and not private_key and not ctx["has_config_file"]:
            raise ValueError(
                "Network Python checks require ssh_password/ssh_key credential or an uploaded device config"
            )
        return run_script_locally_with_resource_env(
            hostname=host.hostname.strip(),
            port=host.port or 22,
            username=ctx["username"],
            password=password,
            private_key=private_key,
            script_path=ctx["run_script_path"],
            extra_env=ctx["extra_env"],
            key_passphrase=key_passphrase,
        )
    if not password and not private_key:
        raise ValueError("Python checks require ssh_password or ssh_key credential")
    return run_script_over_python(
        hostname=host.hostname.strip(),
        port=host.port,
        username=ctx["username"],
        password=password,
        private_key=private_key,
        script_path=ctx["run_script_path"],
        known_hosts_entry=ctx["known_hosts_entry"],
        key_passphrase=key_passphrase,
        extra_env=ctx["extra_env"],
    )


def _audit_ansible(host, **ctx) -> str:
    from secaudit_core.credential_auth import ssh_auth_from_credential
    from secaudit_core.models import CredentialType

    from app.tasks.compliance import _host_inventory_entry

    from app.executors.ansible_exec import playbook_without_become

    cred = ctx["cred"]
    if not cred:
        raise ValueError(f"Host '{host.name}' has no credential assigned")
    secret = ctx["secret"]
    content = ctx["run_script_path"].read_text(encoding="utf-8", errors="replace")
    if getattr(cred, "skip_become", False):
        content = playbook_without_become(content)
    play_creds = {"username": ctx["username"]}
    if cred.credential_type == CredentialType.SSH_PASSWORD:
        play_creds["password"] = secret
    elif cred.credential_type == CredentialType.SSH_KEY:
        play_creds["private_key"] = secret
        key_passphrase = ssh_auth_from_credential(cred, secret, settings)[2]
        if key_passphrase:
            play_creds["key_passphrase"] = key_passphrase
    allowed = ctx["allowed"]
    return run_playbook(
        content,
        [_host_inventory_entry(host)],
        credentials=play_creds,
        connection_mode="auto",
        extravars=ctx["extra_env"],
        tags=sorted(allowed) if allowed else None,
    )


def _remediation_winrm(host, **ctx) -> str:
    from secaudit_core.host_credentials import linked_credentials
    from secaudit_core.models import CredentialType

    from app.tasks.compliance import _credential_secret

    winrm_cred = next(
        (item for item in linked_credentials(host) if item.credential_type == CredentialType.WINRM),
        None,
    )
    if not winrm_cred:
        raise ValueError(f"Host '{host.name}' has no winrm credential assigned")
    return run_script_over_winrm(
        hostname=host.hostname,
        port=host.port,
        username=winrm_cred.username or "root",
        password=_credential_secret(winrm_cred),
        script_path=ctx["run_script_path"],
        server_cert_validation=settings.winrm_server_cert_validation_effective,
        extra_env=ctx["extra_env"],
    )


def _remediation_python(host, **ctx) -> str:
    from secaudit_core.network_scope import host_is_network

    if host_is_network(host):
        return run_script_locally_with_resource_env(
            hostname=host.hostname.strip(),
            port=host.port or 22,
            username=ctx["username"],
            password=ctx["password"],
            private_key=ctx["private_key"],
            script_path=ctx["run_script_path"],
            key_passphrase=ctx["key_passphrase"],
            extra_env=ctx["extra_env"],
        )
    return run_script_over_python(
        hostname=host.hostname,
        port=host.port or 22,
        username=ctx["username"],
        password=ctx["password"],
        private_key=ctx["private_key"],
        script_path=ctx["run_script_path"],
        known_hosts_entry=ctx["known_hosts_entry"],
        key_passphrase=ctx["key_passphrase"],
        extra_env=ctx["extra_env"],
    )


def _remediation_ansible(host, **ctx) -> str:
    from secaudit_core.models import CredentialType

    from app.tasks.compliance import _become_kwargs

    cred = ctx["cred"]
    content = ctx["run_script_path"].read_text(encoding="utf-8", errors="replace")
    inv = [
        {
            "name": host.name.strip(),
            "hostname": host.hostname.strip(),
            "port": host.port or 22,
            "ansible_vars": {},
            "ssh_known_hosts_entry": ctx["known_hosts_entry"],
        }
    ]
    creds: dict = {"username": ctx["username"]}
    if cred.credential_type == CredentialType.SSH_PASSWORD:
        creds["password"] = ctx["secret"]
    elif cred.credential_type == CredentialType.SSH_KEY:
        creds["private_key"] = ctx["secret"]
        if ctx["key_passphrase"]:
            creds["key_passphrase"] = ctx["key_passphrase"]
    elif cred.credential_type == CredentialType.WINRM:
        creds["password"] = ctx["secret"]
        inv[0]["ansible_vars"] = {"ansible_connection": "winrm"}
    become = _become_kwargs(cred)
    if become.get("become_method"):
        creds["become_method"] = become["become_method"]
        creds["become_username"] = become.get("become_username") or "root"
        if become.get("become_password"):
            creds["become_password"] = become["become_password"]
    ansible_vars: dict = {"secaudit_remediate_rules": ctx["tags"] or []}
    if ctx["extra_env"]:
        ansible_vars.update(ctx["extra_env"])
    return run_playbook(
        content,
        inv,
        credentials=creds,
        connection_mode="auto",
        check_mode=ctx["check_mode"],
        tags=ctx["tags"],
        extravars=ansible_vars,
    )


def _remediation_ssh(host, **ctx) -> str:
    from app.tasks.compliance import _become_kwargs

    return run_package_script_over_ssh(
        hostname=host.hostname,
        port=host.port or 22,
        username=ctx["username"],
        password=ctx["password"],
        private_key=ctx["private_key"],
        package_dir=ctx["package_dir"],
        script_file=ctx["script"].script_file,
        known_hosts_entry=ctx["known_hosts_entry"],
        key_passphrase=ctx["key_passphrase"],
        extra_env=ctx["extra_env"],
        script_content_override=ctx["script_override"],
        **_become_kwargs(ctx["cred"]),
    )


AUDIT_EXECUTORS: dict[ExecutionType, ExecutorAdapter] = {
    ExecutionType.SSH: ExecutorAdapter(ExecutionType.SSH, _audit_ssh),
    ExecutionType.WINRM: ExecutorAdapter(ExecutionType.WINRM, _audit_winrm),
    ExecutionType.PYTHON: ExecutorAdapter(ExecutionType.PYTHON, _audit_python),
    ExecutionType.ANSIBLE: ExecutorAdapter(ExecutionType.ANSIBLE, _audit_ansible),
}

REMEDIATION_EXECUTORS: dict[ExecutionType, ExecutorAdapter] = {
    ExecutionType.SSH: ExecutorAdapter(ExecutionType.SSH, _remediation_ssh),
    ExecutionType.WINRM: ExecutorAdapter(ExecutionType.WINRM, _remediation_winrm),
    ExecutionType.PYTHON: ExecutorAdapter(ExecutionType.PYTHON, _remediation_python),
    ExecutionType.ANSIBLE: ExecutorAdapter(ExecutionType.ANSIBLE, _remediation_ansible),
}


def run_audit_script(host, execution_type: ExecutionType, **ctx) -> str:
    adapter = AUDIT_EXECUTORS.get(execution_type)
    if adapter is None:
        raise NotImplementedError(f"Execution type '{execution_type.value}' is not supported")
    adapter.connect(host, **ctx)
    return adapter.run(host, **ctx)


def run_remediation_script(host, execution_type: ExecutionType, **ctx) -> str:
    adapter = REMEDIATION_EXECUTORS.get(execution_type)
    if adapter is None:
        raise NotImplementedError(f"Execution type '{execution_type.value}' is not supported")
    adapter.connect(host, **ctx)
    return adapter.run(host, **ctx)
