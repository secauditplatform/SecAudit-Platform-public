import base64
import secrets
import threading
from pathlib import Path

import winrm
from secaudit_core.service_credentials import powershell_env_prefix
from secaudit_core.settings import SecAuditSettings
from secaudit_core.tracing import start_span
from winrm.exceptions import WinRMTransportError

from app.cancel_context import get_cancel_event, raise_if_cancelled

_settings = SecAuditSettings()

WINRM_HTTP_PORT = 5985
WINRM_HTTPS_PORT = 5986
SSH_DEFAULT_PORT = 22
# Ports commonly stored on Windows hosts from inventory discovery (not WinRM).
WINRM_DISCOVERY_PORTS = frozenset({22, 0, 139, 445, 3389})
# pywinrm run_ps() wraps content in `powershell -encodedcommand ...` (~8191 char Windows limit).
WINRM_MAX_INLINE_ENCODED_CHARS = 7000
# Upper bound for binary search; each chunk is embedded in Set/Add-Content via -EncodedCommand.
WINRM_B64_UPLOAD_CHUNK_CHARS = 1500


def normalize_winrm_port(port: int | None) -> int:
    """Map discovery/SSH ports to WinRM HTTP; keep explicit WinRM ports."""
    value = int(port or 0)
    if value in (WINRM_HTTP_PORT, WINRM_HTTPS_PORT):
        return value
    if value in WINRM_DISCOVERY_PORTS or value <= 0:
        return WINRM_HTTP_PORT
    return value


def winrm_use_ssl(port: int) -> bool:
    return int(port) == WINRM_HTTPS_PORT


def iter_winrm_targets(port: int) -> list[tuple[int, bool]]:
    """Return WinRM (port, use_ssl) attempts in priority order."""
    normalized = normalize_winrm_port(port)
    if normalized == WINRM_HTTPS_PORT:
        ordered = [(WINRM_HTTPS_PORT, True), (WINRM_HTTP_PORT, False)]
    else:
        # Default and discovery ports: prefer HTTP WinRM, then HTTPS.
        ordered = [(WINRM_HTTP_PORT, False), (WINRM_HTTPS_PORT, True)]
        if normalized not in (WINRM_HTTP_PORT, WINRM_HTTPS_PORT):
            ordered.insert(0, (normalized, winrm_use_ssl(normalized)))

    seen: set[tuple[int, bool]] = set()
    targets: list[tuple[int, bool]] = []
    for target in ordered:
        if target not in seen:
            seen.add(target)
            targets.append(target)
    return targets


def _encoded_ps_command_length(ps_command: str) -> int:
    encoded = base64.b64encode(ps_command.encode("utf-16-le")).decode("ascii")
    return len(encoded) + len("powershell -encodedcommand ")


def _should_stage_ps_script(ps_command: str) -> bool:
    return _encoded_ps_command_length(ps_command) > WINRM_MAX_INLINE_ENCODED_CHARS


def _ps_single_quoted(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _safe_script_stem(stem: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in stem)
    return (safe[:64] or "script")


def _build_temp_cleanup_command(filename: str) -> str:
    """Remove a temp artifact if present; must not fail when the file is missing."""
    return (
        f"$ProgressPreference='SilentlyContinue'; "
        f"$p = Join-Path $env:TEMP {_ps_single_quoted(filename)}; "
        f"if (Test-Path -LiteralPath $p) {{ Remove-Item -LiteralPath $p -Force }}"
    )


def _build_b64_chunk_command(b64_name: str, chunk: str, *, append: bool) -> str:
    writer = "Add-Content" if append else "Set-Content"
    return (
        f"$ProgressPreference='SilentlyContinue'; "
        f"$path = Join-Path $env:TEMP {_ps_single_quoted(b64_name)}; "
        f"{writer} -LiteralPath $path -Value {_ps_single_quoted(chunk)} "
        f"-NoNewline -Encoding ascii; "
        f"if (-not (Test-Path -LiteralPath $path)) {{ "
        f"throw 'SecAudit: failed to write staged payload chunk' }}"
    )


def _max_b64_upload_chunk_chars(b64_name: str, *, append: bool) -> int:
    """Return the largest chunk size that still fits in WinRM's encoded-command limit."""
    low, high = 1, WINRM_B64_UPLOAD_CHUNK_CHARS
    best = 1
    while low <= high:
        mid = (low + high) // 2
        ps = _build_b64_chunk_command(b64_name, "A" * mid, append=append)
        if _encoded_ps_command_length(ps) <= WINRM_MAX_INLINE_ENCODED_CHARS:
            best = mid
            low = mid + 1
        else:
            high = mid - 1
    return best


def _is_connectivity_error(exc: BaseException) -> bool:
    markers = (
        "connection refused",
        "failed to establish a new connection",
        "max retries exceeded",
        "timed out",
        "connection reset",
        "actively refused",
        "errno 111",
        "errno 110",
        "no route to host",
        "name or service not known",
        "temporary failure in name resolution",
    )
    chain: list[BaseException] = []
    current: BaseException | None = exc
    while current is not None and current not in chain:
        chain.append(current)
        current = current.__cause__ or current.__context__

    for item in chain:
        text = str(item).lower()
        if any(marker in text for marker in markers):
            return True
    return isinstance(exc, (WinRMTransportError, ConnectionError, OSError))


def _checked_output(result, *, success_codes: tuple[int, ...] = (0,)) -> str:
    """Accept only documented PowerShell success codes and retain diagnostics."""
    stdout = result.std_out.decode("utf-8", errors="replace") if result.std_out else ""
    stderr = result.std_err.decode("utf-8", errors="replace") if result.std_err else ""
    if result.status_code not in success_codes:
        stderr_detail = stderr.strip()
        if stderr_detail.startswith("#< CLIXML") and "Preparing modules for first use" in stderr_detail:
            stderr_detail = (
                "PowerShell returned only remoting progress records in stderr "
                "(likely a non-zero exit from a cmdlet with -ErrorAction SilentlyContinue). "
                f"Raw stderr:\n{stderr_detail}"
            )
        raise RuntimeError(
            f"PowerShell exited with code {result.status_code}"
            f"\nstdout:\n{stdout or '<empty>'}"
            f"\nstderr:\n{stderr_detail or '<empty>'}"
        )
    return stdout if stdout.strip() else stderr


def _invoke_run_ps(
    session: winrm.Session,
    ps_command: str,
    cancel_event: threading.Event | None,
):
    raise_if_cancelled()
    result = session.run_ps(ps_command)
    if cancel_event and cancel_event.is_set():
        raise InterruptedError("Job run cancelled")
    return result


def _run_ps_script_staged(
    session: winrm.Session,
    ps_command: str,
    script_stem: str,
    cancel_event: threading.Event | None,
):
    token = secrets.token_hex(8)
    safe_stem = _safe_script_stem(script_stem)
    b64_name = f"secaudit_{safe_stem}_{token}.b64"
    script_name = f"secaudit_{safe_stem}_{token}.ps1"
    payload_b64 = base64.b64encode(ps_command.encode("utf-8")).decode("ascii")

    _invoke_run_ps(
        session,
        _build_temp_cleanup_command(b64_name),
        cancel_event,
    )

    index = 0
    while index < len(payload_b64):
        append = index > 0
        chunk_size = _max_b64_upload_chunk_chars(b64_name, append=append)
        chunk = payload_b64[index : index + chunk_size]
        _checked_output(
            _invoke_run_ps(
                session,
                _build_b64_chunk_command(b64_name, chunk, append=append),
                cancel_event,
            )
        )
        index += chunk_size

    return _invoke_run_ps(
        session,
        f"""$ProgressPreference='SilentlyContinue'
$ErrorActionPreference='Continue'
$b64Path = Join-Path $env:TEMP {_ps_single_quoted(b64_name)}
$scriptPath = Join-Path $env:TEMP {_ps_single_quoted(script_name)}
if (-not (Test-Path -LiteralPath $b64Path)) {{
  throw "SecAudit: staged payload file not found: $b64Path"
}}
$raw = Get-Content -LiteralPath $b64Path -Raw
[IO.File]::WriteAllBytes($scriptPath, [Convert]::FromBase64String($raw))
if (Test-Path -LiteralPath $b64Path) {{ Remove-Item -LiteralPath $b64Path -Force }}
try {{
  & $scriptPath
}} finally {{
  if (Test-Path -LiteralPath $scriptPath) {{ Remove-Item -LiteralPath $scriptPath -Force }}
}}""",
        cancel_event,
    )


def _execute_ps_script(
    session: winrm.Session,
    ps_command: str,
    script_stem: str,
    cancel_event: threading.Event | None,
):
    if _should_stage_ps_script(ps_command):
        return _run_ps_script_staged(session, ps_command, script_stem, cancel_event)
    return _invoke_run_ps(session, ps_command, cancel_event)


def _run_winrm_once(
    *,
    hostname: str,
    port: int,
    use_ssl: bool,
    username: str,
    password: str,
    ps_command: str,
    script_stem: str,
    timeout: int,
    server_cert_validation: str,
    cancel_event: threading.Event | None,
) -> str:
    scheme = "https" if use_ssl else "http"
    endpoint = f"{scheme}://{hostname}:{port}/wsman"
    span_attrs = {
        "secaudit.executor": "winrm",
        "net.peer.name": hostname,
        "net.peer.port": port,
        "enduser.id": username,
        "secaudit.winrm.cert_validation": server_cert_validation,
        "secaudit.winrm.tls": use_ssl,
        "secaudit.winrm.staged": _should_stage_ps_script(ps_command),
    }
    with start_span(f"executor.winrm {scheme}:{port}", attributes=span_attrs, kind="client"):
        session = winrm.Session(
            endpoint,
            auth=(username, password),
            transport="ntlm",
            server_cert_validation=server_cert_validation,
            operation_timeout_sec=timeout,
            read_timeout_sec=timeout + 30,
        )

        result = _execute_ps_script(session, ps_command, script_stem, cancel_event)
        return _checked_output(result)


def run_script_over_winrm(
    hostname: str,
    port: int,
    username: str,
    password: str,
    script_path: Path,
    use_ssl: bool | None = None,
    timeout: int = 900,
    server_cert_validation: str | None = None,
    cancel_event: threading.Event | None = None,
    extra_env: dict[str, str] | None = None,
) -> str:
    if not script_path.exists():
        raise FileNotFoundError(f"Script not found: {script_path}")

    cancel_event = cancel_event if cancel_event is not None else get_cancel_event()
    raise_if_cancelled()

    script_content = script_path.read_text(encoding="utf-8", errors="replace")
    validation = server_cert_validation or _settings.winrm_server_cert_validation_effective

    ps_command = script_content
    if script_path.suffix.lower() != ".ps1":
        ps_command = f"$ErrorActionPreference='Continue'\n{script_content}"
    env_prefix = powershell_env_prefix(extra_env)
    if env_prefix:
        ps_command = env_prefix + ps_command

    if use_ssl is not None:
        targets = [(port, use_ssl)]
    else:
        targets = iter_winrm_targets(port)

    errors: list[str] = []
    for target_port, target_ssl in targets:
        scheme = "https" if target_ssl else "http"
        try:
            return _run_winrm_once(
                hostname=hostname,
                port=target_port,
                use_ssl=target_ssl,
                username=username,
                password=password,
                ps_command=ps_command,
                script_stem=script_path.stem,
                timeout=timeout,
                server_cert_validation=validation,
                cancel_event=cancel_event,
            )
        except InterruptedError:
            raise
        except Exception as exc:
            if not _is_connectivity_error(exc) or len(targets) == 1:
                raise
            errors.append(f"{scheme}://{hostname}:{target_port}/wsman: {exc}")

    details = "\n".join(errors) if errors else "no WinRM endpoints attempted"
    endpoint_labels = ", ".join(f"{p}/{'https' if ssl else 'http'}" for p, ssl in targets)
    raise RuntimeError(
        "WinRM connection failed on all attempted endpoints "
        f"({endpoint_labels}):\n{details}"
    )
