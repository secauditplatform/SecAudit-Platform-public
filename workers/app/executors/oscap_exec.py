"""Run OpenSCAP XCCDF / OVAL evaluation on a remote host over SSH."""

from __future__ import annotations

import asyncio
import shlex
import threading
import uuid
from pathlib import Path

import asyncssh
from secaudit_core.oscap import parse_oval_results_xml, parse_xccdf_results_xml
from secaudit_core.settings import SecAuditSettings
from secaudit_core.ssh_connect import build_ssh_connect_kwargs
from secaudit_core.tracing import start_span

from app.cancel_context import get_cancel_event, raise_if_cancelled

_settings = SecAuditSettings()
_thread_local = threading.local()


class OscapNotAvailableError(RuntimeError):
    """Raised when the target host does not have oscap installed."""


def _get_event_loop() -> asyncio.AbstractEventLoop:
    loop = getattr(_thread_local, "loop", None)
    if loop is None or loop.is_closed():
        loop = asyncio.new_event_loop()
        _thread_local.loop = loop
    return loop


def _run_async(coro):
    return _get_event_loop().run_until_complete(coro)


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


def _extract_results_xml(combined: str) -> bytes:
    xml_start = combined.find("<?xml")
    if xml_start < 0:
        xml_start = combined.find("<TestResult")
    if xml_start < 0:
        xml_start = combined.find("<oval_results")
    if xml_start < 0:
        snippet = combined.strip()[-500:]
        raise RuntimeError(f"OpenSCAP produced no results XML. Output: {snippet}")
    return combined[xml_start:].encode("utf-8", errors="replace")


async def _ensure_oscap(conn: asyncssh.SSHClientConnection) -> None:
    check = await conn.run("command -v oscap", timeout=30)
    if check.exit_status != 0 or not (check.stdout or "").strip():
        raise OscapNotAvailableError(
            "OpenSCAP (oscap) is not installed on the target host. "
            "Install open-scap-scanner or use a profile with embedded shell checks."
        )


async def _upload_content(
    conn: asyncssh.SSHClientConnection,
    remote_dir: str,
    content_files: list[Path],
) -> None:
    await conn.run(f"mkdir -p {shlex.quote(remote_dir)}", timeout=30, check=True)
    async with conn.start_sftp_client() as sftp:
        for local in content_files:
            remote = f"{remote_dir}/{local.name}"
            await sftp.put(str(local), remote)


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


async def _run_oscap_eval_async(
    hostname: str,
    port: int,
    username: str,
    password: str | None,
    private_key: str | None,
    benchmark_path: Path,
    content_files: list[Path],
    *,
    mode: str = "xccdf",
    profile_id: str | None = None,
    timeout: int = 1800,
    known_hosts_entry: str | None = None,
    cancel_event: threading.Event | None = None,
    key_passphrase: str | None = None,
) -> tuple[dict[str, str], str]:
    raise_if_cancelled()
    session_id = uuid.uuid4().hex
    remote_dir = f"/tmp/secaudit_scap_{session_id}"
    benchmark_name = benchmark_path.name

    connect_kwargs = _ssh_connect_kwargs(
        hostname, port, username, password, private_key, known_hosts_entry=known_hosts_entry,
        key_passphrase=key_passphrase,
    )

    async with asyncssh.connect(**connect_kwargs) as conn:
        watcher = asyncio.create_task(_watch_cancel(conn, cancel_event))
        try:
            raise_if_cancelled()
            await _ensure_oscap(conn)
            await _upload_content(conn, remote_dir, content_files)

            subcommand = "oval eval" if mode == "oval" else "xccdf eval"
            profile_arg = ""
            if mode == "xccdf" and profile_id:
                profile_arg = f"--profile {shlex.quote(profile_id)} "
            eval_cmd = (
                f"trap 'rm -rf {shlex.quote(remote_dir)}' EXIT; "
                f"cd {shlex.quote(remote_dir)} && "
                f"oscap {subcommand} {profile_arg}--results {shlex.quote('results.xml')} "
                f"{shlex.quote(benchmark_name)} 2>&1; "
                f"EVAL_EXIT=$?; "
                f"if [ -f results.xml ]; then cat results.xml; fi; "
                f"exit $EVAL_EXIT"
            )
            raise_if_cancelled()
            result = await conn.run(eval_cmd, timeout=timeout)
            raise_if_cancelled()
            combined = (result.stdout or "") + (result.stderr or "")

            try:
                xml_content = _extract_results_xml(combined)
            except RuntimeError as exc:
                raise RuntimeError(f"{exc} (exit {result.exit_status})") from exc

            if mode == "oval":
                outcomes = parse_oval_results_xml(xml_content)
                if not outcomes:
                    raise RuntimeError("OVAL results XML contains no definition results")
            else:
                outcomes = parse_xccdf_results_xml(xml_content)
                if not outcomes:
                    raise RuntimeError("OpenSCAP results XML contains no rule-result entries")
            return outcomes, combined
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


def run_oscap_eval_over_ssh(
    hostname: str,
    port: int,
    username: str,
    password: str | None,
    private_key: str | None,
    benchmark_path: Path,
    *,
    content_files: list[Path] | None = None,
    profile_id: str | None = None,
    timeout: int = 1800,
    known_hosts_entry: str | None = None,
    cancel_event: threading.Event | None = None,
    key_passphrase: str | None = None,
) -> tuple[dict[str, str], str]:
    """Evaluate an XCCDF benchmark (or SCAP data-stream) on a remote host via ``oscap``.

    ``content_files`` may include referenced OVAL/CPE files; all are uploaded together so
    ``oscap`` can resolve ``check-content-ref`` hrefs. Defaults to just the benchmark.
    """
    if not benchmark_path.is_file():
        raise FileNotFoundError(f"SCAP benchmark not found: {benchmark_path}")

    cancel_event = cancel_event if cancel_event is not None else get_cancel_event()
    files = _dedupe_content(benchmark_path, content_files)
    span_attrs = {
        "secaudit.executor": "oscap.xccdf",
        "secaudit.benchmark": benchmark_path.name,
        "secaudit.scap_profile_id": profile_id,
        "net.peer.name": hostname,
        "net.peer.port": port,
        "enduser.id": username,
    }
    with start_span(
        f"executor.oscap.xccdf {benchmark_path.name}", attributes=span_attrs, kind="client"
    ):
        return _run_async(
            _run_oscap_eval_async(
                hostname=hostname,
                port=port,
                username=username,
                password=password,
                private_key=private_key,
                benchmark_path=benchmark_path,
                content_files=files,
                mode="xccdf",
                profile_id=profile_id,
                timeout=timeout,
                known_hosts_entry=known_hosts_entry,
                cancel_event=cancel_event,
                key_passphrase=key_passphrase,
            )
        )


def run_oval_eval_over_ssh(
    hostname: str,
    port: int,
    username: str,
    password: str | None,
    private_key: str | None,
    oval_path: Path,
    *,
    timeout: int = 1800,
    known_hosts_entry: str | None = None,
    cancel_event: threading.Event | None = None,
    key_passphrase: str | None = None,
) -> tuple[dict[str, str], str]:
    """Evaluate a standalone OVAL definitions file on a remote host via ``oscap oval eval``."""
    if not oval_path.is_file():
        raise FileNotFoundError(f"OVAL definitions not found: {oval_path}")

    cancel_event = cancel_event if cancel_event is not None else get_cancel_event()
    span_attrs = {
        "secaudit.executor": "oscap.oval",
        "secaudit.benchmark": oval_path.name,
        "net.peer.name": hostname,
        "net.peer.port": port,
        "enduser.id": username,
    }
    with start_span(f"executor.oscap.oval {oval_path.name}", attributes=span_attrs, kind="client"):
        return _run_async(
            _run_oscap_eval_async(
                hostname=hostname,
                port=port,
                username=username,
                password=password,
                private_key=private_key,
                benchmark_path=oval_path,
                content_files=[oval_path],
                mode="oval",
                timeout=timeout,
                known_hosts_entry=known_hosts_entry,
                cancel_event=cancel_event,
                key_passphrase=key_passphrase,
            )
        )


def _dedupe_content(benchmark_path: Path, content_files: list[Path] | None) -> list[Path]:
    files: list[Path] = [benchmark_path]
    seen = {benchmark_path.name}
    for path in content_files or []:
        if path.is_file() and path.name not in seen:
            files.append(path)
            seen.add(path.name)
    return files
