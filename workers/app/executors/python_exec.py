import asyncio
import os
import subprocess
import sys
import tempfile
import threading
from pathlib import Path

import asyncssh
from secaudit_core.service_credentials import shell_export_prefix
from secaudit_core.settings import SecAuditSettings
from secaudit_core.ssh_connect import build_ssh_connect_kwargs
from secaudit_core.tracing import start_span

from app.cancel_context import get_cancel_event, raise_if_cancelled
from app.executors.ssh import unique_remote_script_path

_settings = SecAuditSettings()

# Keep OS/runtime basics for Netmiko/Paramiko; never inherit worker secrets.
_LOCAL_ENV_PASSTHROUGH = frozenset(
    {
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "SYSTEMDRIVE",
        "WINDIR",
        "COMSPEC",
        "TEMP",
        "TMP",
        "TMPDIR",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LC_MESSAGES",
        "TZ",
        "TERM",
        "HOME",
        "USER",
        "LOGNAME",
        "USERNAME",
        "USERPROFILE",
        "NUMBER_OF_PROCESSORS",
        "PROCESSOR_ARCHITECTURE",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "PYTHONIOENCODING",
        "PYTHONUTF8",
    }
)


def _isolated_local_script_env() -> dict[str, str]:
    """Build a minimal env so package scripts cannot read worker secrets from os.environ."""
    env: dict[str, str] = {}
    for key, value in os.environ.items():
        if key.upper() in _LOCAL_ENV_PASSTHROUGH:
            env[key] = value
    # Prefer the same interpreter's environment encoding defaults.
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _checked_output(result, *, success_codes: tuple[int, ...] = (0,)) -> str:
    """Accept only documented success codes while retaining both output streams."""
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    if result.exit_status not in success_codes:
        raise RuntimeError(
            f"Python script exited with code {result.exit_status}"
            f"\nstdout:\n{stdout or '<empty>'}"
            f"\nstderr:\n{stderr or '<empty>'}"
        )
    return stdout if stdout.strip() else stderr


def _checked_local_output(completed: subprocess.CompletedProcess[str]) -> str:
    stdout = completed.stdout or ""
    stderr = completed.stderr or ""
    if completed.returncode != 0:
        raise RuntimeError(
            f"Python script exited with code {completed.returncode}"
            f"\nstdout:\n{stdout or '<empty>'}"
            f"\nstderr:\n{stderr or '<empty>'}"
        )
    return stdout if stdout.strip() else stderr


def run_script_locally_with_resource_env(
    *,
    hostname: str,
    port: int,
    username: str,
    password: str | None,
    private_key: str | None,
    script_path: Path,
    timeout: int = 900,
    cancel_event: threading.Event | None = None,
    extra_env: dict[str, str] | None = None,
    key_passphrase: str | None = None,
) -> str:
    """Run a package Python check on the worker (Netmiko/Paramiko reach the device).

    Network devices cannot execute uploaded python3 scripts. Checks that talk to
    devices via netmiko expect resource_ip / resource_user / resource_pass (and
    optionally ssh_private_key_path) in the environment — same convention as
    Juniper_CRE_NUP / Cisco ONLINE scripts.

    When SECAUDIT_OFFLINE_MODE is set (config_upload / both with uploaded config),
    resource_* credentials are omitted so package collectors stay offline and
    evaluate the vendor profile against the uploaded config file.
    """
    if not script_path.exists():
        raise FileNotFoundError(f"Script not found: {script_path}")

    cancel_event = cancel_event if cancel_event is not None else get_cancel_event()
    raise_if_cancelled()

    package_dir = script_path.resolve().parent
    # Do not copy worker os.environ (SECRET_KEY, DB/Redis/Vault URLs, etc.).
    env = _isolated_local_script_env()
    if extra_env:
        # Explicit job/package extras only (e.g. SECAUDIT_CONFIG_FILE).
        env.update({str(k): str(v) for k, v in extra_env.items() if v is not None})

    offline = str(env.get("SECAUDIT_OFFLINE_MODE", "")).strip().lower() in {"1", "true", "yes"}
    if not offline:
        env["resource_ip"] = hostname.strip()
        env["resource_user"] = username
        env["resource_port"] = str(port)
        if password:
            env["resource_pass"] = password
    env["PYTHONPATH"] = str(package_dir)

    key_path: Path | None = None
    scratch_dir: tempfile.TemporaryDirectory[str] | None = None
    try:
        scratch_dir = tempfile.TemporaryDirectory(prefix="secaudit_net_home_")
        env["HOME"] = scratch_dir.name
        env["USERPROFILE"] = scratch_dir.name
        env["TEMP"] = scratch_dir.name
        env["TMP"] = scratch_dir.name
        env["TMPDIR"] = scratch_dir.name

        if private_key and not offline:
            key_file = tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                suffix=".pem",
                prefix="secaudit_net_key_",
                dir=scratch_dir.name,
                delete=False,
            )
            with key_file:
                key_file.write(private_key)
                if not private_key.endswith("\n"):
                    key_file.write("\n")
            key_path = Path(key_file.name)
            try:
                key_path.chmod(0o600)
            except OSError:
                pass
            env["ssh_private_key_path"] = str(key_path)
            if key_passphrase:
                env["ssh_private_key_passphrase"] = key_passphrase

        span_attrs = {
            "secaudit.executor": "python_local",
            "secaudit.script": script_path.name,
            "net.peer.name": hostname if not offline else "offline",
            "net.peer.port": port if not offline else 0,
            "enduser.id": username if not offline else "offline",
            "secaudit.offline": offline,
        }
        with start_span(f"executor.python.local {script_path.name}", attributes=span_attrs, kind="client"):
            raise_if_cancelled()
            completed = subprocess.run(
                [sys.executable, "-B", str(script_path.resolve())],
                cwd=str(package_dir),
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
            )
            raise_if_cancelled()
            return _checked_local_output(completed)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"Local Python script timed out after {timeout}s: {script_path.name}") from exc
    finally:
        if key_path is not None:
            try:
                key_path.unlink(missing_ok=True)
            except OSError:
                pass
        if scratch_dir is not None:
            scratch_dir.cleanup()


async def _watch_cancel(
    conn: asyncssh.SSHClientConnection,
    cancel_event: threading.Event | None,
) -> None:
    if cancel_event is None:
        return
    while not cancel_event.is_set():
        await asyncio.sleep(0.25)
    try:
        conn.close()
    except Exception:
        pass


async def _run_python_async(
    hostname: str,
    port: int,
    username: str,
    password: str | None,
    private_key: str | None,
    script_content: str,
    remote_path: str,
    timeout: int = 900,
    known_hosts_entry: str | None = None,
    cancel_event: threading.Event | None = None,
    key_passphrase: str | None = None,
    extra_env: dict[str, str] | None = None,
) -> str:
    raise_if_cancelled()
    connect_kwargs = build_ssh_connect_kwargs(
        host=hostname,
        port=port,
        username=username,
        password=password,
        private_key=private_key,
        settings=_settings,
        known_hosts_entry=known_hosts_entry,
        key_passphrase=key_passphrase,
    )
    env_prefix = shell_export_prefix(extra_env)

    async with asyncssh.connect(**connect_kwargs) as conn:
        watcher = asyncio.create_task(_watch_cancel(conn, cancel_event))
        try:
            raise_if_cancelled()
            async with conn.start_sftp_client() as sftp:
                async with sftp.open(remote_path, "w") as remote_file:
                    await remote_file.write(script_content)

            raise_if_cancelled()
            result = await conn.run(
                f"trap 'rm -f {remote_path}' EXIT; "
                f"{env_prefix}"
                f"timeout --foreground {timeout} "
                f"sh -c 'python3 {remote_path} 2>&1 || python {remote_path} 2>&1'; "
                f"EXIT_CODE=$?; "
                f"if [ $EXIT_CODE -eq 124 ]; then "
                f"echo 'Remote script timed out after {timeout}s' >&2; "
                f"fi; "
                f"exit $EXIT_CODE",
                timeout=timeout + 30,
            )
            raise_if_cancelled()
            return _checked_output(result)
        except (asyncio.CancelledError, asyncssh.ConnectionLost, asyncssh.DisconnectError) as exc:
            if cancel_event and cancel_event.is_set():
                raise InterruptedError("Job run cancelled") from exc
            raise
        finally:
            watcher.cancel()
            try:
                await watcher
            except asyncio.CancelledError:
                pass


def run_script_over_ssh(
    hostname: str,
    port: int,
    username: str,
    password: str | None,
    private_key: str | None,
    script_path: Path,
    timeout: int = 900,
    known_hosts_entry: str | None = None,
    cancel_event: threading.Event | None = None,
    key_passphrase: str | None = None,
    extra_env: dict[str, str] | None = None,
) -> str:
    if not script_path.exists():
        raise FileNotFoundError(f"Script not found: {script_path}")

    cancel_event = cancel_event if cancel_event is not None else get_cancel_event()
    raise_if_cancelled()

    script_content = script_path.read_text(encoding="utf-8", errors="replace")
    remote_path = unique_remote_script_path(script_path.stem, suffix=".py")

    span_attrs = {
        "secaudit.executor": "python",
        "secaudit.script": script_path.name,
        "net.peer.name": hostname,
        "net.peer.port": port,
        "enduser.id": username,
    }
    with start_span(f"executor.python {script_path.name}", attributes=span_attrs, kind="client"):
        return asyncio.run(
            _run_python_async(
                hostname=hostname,
                port=port,
                username=username,
                password=password,
                private_key=private_key,
                script_content=script_content,
                remote_path=remote_path,
                timeout=timeout,
                known_hosts_entry=known_hosts_entry,
                cancel_event=cancel_event,
                key_passphrase=key_passphrase,
                extra_env=extra_env,
            )
        )
