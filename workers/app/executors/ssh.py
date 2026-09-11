import asyncio
import secrets
import shlex
import tarfile
import tempfile
import threading
import uuid
from io import BytesIO
from pathlib import Path

import asyncssh
from secaudit_core.package_paths import resolve_script_under_package
from secaudit_core.service_credentials import shell_export_prefix, service_script_cli_suffix
from secaudit_core.settings import SecAuditSettings
from secaudit_core.ssh_connect import build_ssh_connect_kwargs
from secaudit_core.tracing import start_span

from app.cancel_context import get_cancel_event, raise_if_cancelled

_settings = SecAuditSettings()
_thread_local = threading.local()


def _checked_output(
    result, *, operation: str = "Remote command", success_codes: tuple[int, ...] = (0,)
) -> str:
    """Return diagnostic output only for explicitly successful remote exit codes."""
    stdout = result.stdout or ""
    stderr = result.stderr or ""
    if result.exit_status not in success_codes:
        detail = (
            f"{operation} exited with code {result.exit_status}"
            f"\nstdout:\n{stdout or '<empty>'}"
            f"\nstderr:\n{stderr or '<empty>'}"
        )
        raise RuntimeError(detail)
    return stdout if stdout.strip() else stderr


def _get_event_loop() -> asyncio.AbstractEventLoop:
    loop = getattr(_thread_local, "loop", None)
    if loop is None or loop.is_closed():
        loop = asyncio.new_event_loop()
        _thread_local.loop = loop
    return loop


def _run_async(coro):
    return _get_event_loop().run_until_complete(coro)


def unique_remote_script_path(stem: str, suffix: str = ".sh") -> str:
    """Build a per-run remote temp path so concurrent jobs cannot collide."""
    token = secrets.token_hex(8)
    safe_stem = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in stem)[:64] or "script"
    return f"/tmp/secaudit_{safe_stem}_{token}{suffix}"


def _ssh_connect_kwargs(
    hostname: str,
    port: int,
    username: str,
    password: str | None,
    private_key: str | None,
    known_hosts_entry: str | None = None,
    key_passphrase: str | None = None,
) -> dict:
    return build_ssh_connect_kwargs(
        host=hostname,
        port=port,
        username=username,
        password=password,
        private_key=private_key,
        settings=_settings,
        known_hosts_entry=known_hosts_entry,
        key_passphrase=key_passphrase,
    )


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


async def _run_script_async(
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
    connect_kwargs = _ssh_connect_kwargs(
        hostname, port, username, password, private_key, known_hosts_entry=known_hosts_entry,
        key_passphrase=key_passphrase,
    )
    env_prefix = shell_export_prefix(extra_env)
    cli_suffix = service_script_cli_suffix(extra_env)

    async with asyncssh.connect(**connect_kwargs) as conn:
        watcher = asyncio.create_task(_watch_cancel(conn, cancel_event))
        try:
            raise_if_cancelled()
            async with conn.start_sftp_client() as sftp:
                async with sftp.open(remote_path, "w") as remote_file:
                    await remote_file.write(script_content)

            raise_if_cancelled()
            # trap guarantees cleanup even if the remote process is interrupted.
            result = await conn.run(
                f"trap 'rm -f {remote_path}' EXIT; "
                f"{env_prefix}"
                f"chmod +x {remote_path} && bash {remote_path}{cli_suffix}; EXIT_CODE=$?; exit $EXIT_CODE",
                timeout=timeout,
            )
            raise_if_cancelled()
            return _checked_output(result, operation="Remote script")
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
    remote_path = unique_remote_script_path(script_path.stem, suffix=".sh")

    span_attrs = {
        "secaudit.executor": "ssh",
        "secaudit.script": script_path.name,
        "net.peer.name": hostname,
        "net.peer.port": port,
        "enduser.id": username,
    }
    with start_span(f"executor.ssh {script_path.name}", attributes=span_attrs, kind="client"):
        return _run_async(
            _run_script_async(
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


def _build_package_archive(package_dir: Path) -> Path:
    from secaudit_core.package_paths import (
        SHELL_SCRIPT_SUFFIXES,
        normalize_shell_script_bytes,
    )

    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".tar.gz")
    temp_file.close()
    archive_path = Path(temp_file.name)
    with tarfile.open(archive_path, "w:gz") as archive:
        for path in sorted(package_dir.rglob("*")):
            if not path.is_file():
                continue
            arcname = path.relative_to(package_dir).as_posix()
            if path.suffix.lower() in SHELL_SCRIPT_SUFFIXES:
                data = normalize_shell_script_bytes(path.read_bytes())
                info = tarfile.TarInfo(name=arcname)
                info.size = len(data)
                info.mtime = path.stat().st_mtime
                info.mode = path.stat().st_mode & 0o777
                archive.addfile(info, fileobj=BytesIO(data))
            else:
                archive.add(path, arcname=arcname)
    return archive_path


async def _run_package_script_async(
    hostname: str,
    port: int,
    username: str,
    password: str | None,
    private_key: str | None,
    package_dir: Path,
    script_file: str,
    timeout: int = 1800,
    known_hosts_entry: str | None = None,
    cancel_event: threading.Event | None = None,
    key_passphrase: str | None = None,
) -> str:
    raise_if_cancelled()
    resolved_script = resolve_script_under_package(package_dir, script_file)
    script_path = resolved_script.relative_to(package_dir.resolve()).as_posix()
    archive_path = _build_package_archive(package_dir)
    remote_archive = f"/tmp/secaudit_pkg_{uuid.uuid4().hex}.tar.gz"
    remote_dir = f"/tmp/secaudit_pkg_{uuid.uuid4().hex}"
    q_remote_dir = shlex.quote(remote_dir)
    q_remote_archive = shlex.quote(remote_archive)
    q_script_path = shlex.quote(script_path)
    q_bash_script = shlex.quote(f"./{script_path}")

    try:
        connect_kwargs = _ssh_connect_kwargs(
            hostname, port, username, password, private_key, known_hosts_entry=known_hosts_entry,
            key_passphrase=key_passphrase,
        )
    except ValueError:
        archive_path.unlink(missing_ok=True)
        raise

    try:
        async with asyncssh.connect(**connect_kwargs) as conn:
            watcher = asyncio.create_task(_watch_cancel(conn, cancel_event))
            try:
                raise_if_cancelled()
                async with conn.start_sftp_client() as sftp:
                    await sftp.put(str(archive_path), remote_archive)

                raise_if_cancelled()
                result = await conn.run(
                    f"trap 'rm -rf {q_remote_dir} {q_remote_archive}' EXIT; "
                    f"mkdir -p {q_remote_dir} && "
                    f"tar -xzf {q_remote_archive} -C {q_remote_dir} && "
                    f"chmod +x {q_remote_dir}/{q_script_path} && "
                    f"cd {q_remote_dir} && bash {q_bash_script}; "
                    f"EXIT_CODE=$?; exit $EXIT_CODE",
                    timeout=timeout,
                )
                raise_if_cancelled()
                return _checked_output(result, operation="Remediation script")
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
    finally:
        archive_path.unlink(missing_ok=True)


def run_package_script_over_ssh(
    hostname: str,
    port: int,
    username: str,
    password: str | None,
    private_key: str | None,
    package_dir: Path,
    script_file: str,
    timeout: int = 1800,
    known_hosts_entry: str | None = None,
    cancel_event: threading.Event | None = None,
    key_passphrase: str | None = None,
) -> str:
    if not package_dir.is_dir():
        raise FileNotFoundError(f"Package directory not found: {package_dir}")

    cancel_event = cancel_event if cancel_event is not None else get_cancel_event()
    raise_if_cancelled()

    span_attrs = {
        "secaudit.executor": "ssh.package",
        "secaudit.package": package_dir.name,
        "secaudit.script": script_file,
        "net.peer.name": hostname,
        "net.peer.port": port,
        "enduser.id": username,
    }
    with start_span(
        f"executor.ssh.package {script_file}", attributes=span_attrs, kind="client"
    ):
        return _run_async(
            _run_package_script_async(
                hostname=hostname,
                port=port,
                username=username,
                password=password,
                private_key=private_key,
                package_dir=package_dir,
                script_file=script_file,
                timeout=timeout,
                known_hosts_entry=known_hosts_entry,
                cancel_event=cancel_event,
                key_passphrase=key_passphrase,
            )
        )
