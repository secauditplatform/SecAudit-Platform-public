import asyncio
import json
import logging
import os
import shlex

from fastapi import WebSocket
from starlette.websockets import WebSocketDisconnect

from app.core.auth import AuthUser
from app.core.config import settings
from app.services.console_command_policy import (
    COMMAND_DENIED_MESSAGE,
    validate_console_command,
)

# SECURITY: Commands are validated server-side before spawn. No interactive bash shell.
# Prefer the console sandbox Compose service (CONSOLE_SANDBOX_ENABLED) so commands do not
# run inside the API process. Role gate, CONSOLE_ENABLED, session timeout, and the
# allowlist below are pragmatic mitigations.

console_logger = logging.getLogger("secaudit.console")

PROMPT = "\r\n\033[01;32msecaudit\033[00m:\033[01;34m/tmp\033[00m$ "
WELCOME = (
    "\r\nSecAudit Console — network debugging and system monitoring utilities.\r\n"
    "Commands run inside the console sandbox container with a restricted allowlist.\r\n"
)
WELCOME_DEMO = (
    "\r\nSecAudit Console (demo) — ping only.\r\n"
    "Example: ping -c 4 8.8.8.8\r\n"
)
CONSOLE_CWD = "/var/empty/secaudit-console"


def _limited_env() -> dict[str, str]:
    env = {
        "TERM": "xterm-256color",
        "HOME": CONSOLE_CWD,
        "LANG": "C.UTF-8",
        "PATH": os.environ.get("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"),
    }
    for key in ("LC_ALL", "LC_CTYPE"):
        if key in os.environ:
            env[key] = os.environ[key]
    return env


def _apply_resource_limits() -> None:
    """Linux child limits; called after fork and before exec."""
    import resource

    timeout = max(1, settings.console_command_timeout_seconds)
    limits = (
        (resource.RLIMIT_CPU, (timeout, timeout + 1)),
        (resource.RLIMIT_FSIZE, (0, 0)),
        (resource.RLIMIT_NOFILE, (32, 32)),
        (resource.RLIMIT_NPROC, (16, 16)),
        (resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024)),
    )
    for kind, value in limits:
        try:
            resource.setrlimit(kind, value)
        except (OSError, ValueError):
            continue


async def _send_prompt(websocket: WebSocket) -> None:
    await websocket.send_text(PROMPT)


async def _send_denied(websocket: WebSocket) -> None:
    await websocket.send_text(f"\r\n\x1b[31m{COMMAND_DENIED_MESSAGE}\x1b[0m")
    await _send_prompt(websocket)


async def _stream_command_output(
    websocket: WebSocket,
    process: asyncio.subprocess.Process,
    on_complete: asyncio.Event,
) -> None:
    sent = 0
    try:
        try:
            async with asyncio.timeout(settings.console_command_timeout_seconds):
                if process.stdout:
                    while True:
                        chunk = await process.stdout.read(4096)
                        if not chunk:
                            break
                        remaining = settings.console_command_output_max_bytes - sent
                        if remaining <= 0:
                            await websocket.send_text("\r\n[output limit reached]\r\n")
                            process.terminate()
                            break
                        chunk = chunk[:remaining]
                        sent += len(chunk)
                        await websocket.send_bytes(chunk)
                await process.wait()
        except TimeoutError:
            await websocket.send_text("\r\n[command timed out]\r\n")
            if process.returncode is None:
                process.terminate()
                try:
                    await asyncio.wait_for(process.wait(), timeout=2)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
    finally:
        on_complete.set()
        await _send_prompt(websocket)


async def _start_allowed_command(
    websocket: WebSocket,
    line: str,
    *,
    user: AuthUser | None = None,
) -> tuple[asyncio.subprocess.Process | None, asyncio.Event | None]:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        await _send_prompt(websocket)
        return None, None

    allowed, error = validate_console_command(stripped, demo_mode=settings.demo_mode)
    if not allowed:
        await websocket.send_text(f"\r\n\x1b[31m{error}\x1b[0m")
        await _send_prompt(websocket)
        return None, None

    console_logger.info(
        "console command",
        extra={
            "event": "console.command",
            "username": user.username if user else "unknown",
            "user_sub": user.sub if user else None,
            "command": stripped,
        },
    )

    if stripped == "clear":
        await websocket.send_text("\033[2J\033[H")
        await _send_prompt(websocket)
        return None, None

    try:
        args = shlex.split(stripped)
    except ValueError:
        await _send_denied(websocket)
        return None, None

    try:
        spawn_options = {
            "cwd": CONSOLE_CWD,
            "env": _limited_env(),
        }
        if os.name == "posix":
            spawn_options.update(
                preexec_fn=_apply_resource_limits,
                start_new_session=True,
            )
        process = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            **spawn_options,
        )
    except FileNotFoundError:
        await websocket.send_text(f"\r\n\x1b[31m{args[0]}: command not found\x1b[0m")
        await _send_prompt(websocket)
        return None, None
    except OSError as exc:
        await websocket.send_text(f"\r\n\x1b[31m{exc}\x1b[0m")
        await _send_prompt(websocket)
        return None, None

    complete = asyncio.Event()
    asyncio.create_task(_stream_command_output(websocket, process, complete))
    return process, complete


def _utf8_sequence_length(lead: int) -> int:
    if lead < 0x80:
        return 1
    if lead < 0xC0:
        return 0
    if lead < 0xE0:
        return 2
    if lead < 0xF0:
        return 3
    if lead < 0xF8:
        return 4
    return 0


class _ConsoleInputParser:
    """Strip ANSI/VT escape sequences and decode UTF-8 from terminal input."""

    def __init__(self) -> None:
        self._pending = bytearray()

    def feed(self, data: bytes) -> list[str]:
        self._pending.extend(data)
        events: list[str] = []
        i = 0
        buf = self._pending

        while i < len(buf):
            b = buf[i]

            if b == 0x1B:
                if i + 1 >= len(buf):
                    break
                nxt = buf[i + 1]
                if nxt == ord("["):
                    j = i + 2
                    while j < len(buf):
                        if 0x40 <= buf[j] <= 0x7E:
                            i = j + 1
                            break
                        j += 1
                    else:
                        break
                    continue
                if nxt == ord("O"):
                    if i + 2 >= len(buf):
                        break
                    i += 3
                    continue
                i += 2
                continue

            if b == 0x9B:
                j = i + 1
                while j < len(buf):
                    if 0x40 <= buf[j] <= 0x7E:
                        i = j + 1
                        break
                    j += 1
                else:
                    break
                continue

            if b in (0x0D, 0x0A, 0x03, 0x08, 0x7F, 0x09):
                events.append(chr(b))
                i += 1
                continue

            if 0x20 <= b <= 0x7E:
                events.append(chr(b))
                i += 1
                continue

            if b & 0x80:
                seq_len = _utf8_sequence_length(b)
                if seq_len == 0 or i + seq_len > len(buf):
                    break
                try:
                    char = bytes(buf[i : i + seq_len]).decode("utf-8")
                except UnicodeDecodeError:
                    i += 1
                    continue
                if char.isprintable():
                    events.append(char)
                i += seq_len
                continue

            i += 1

        del buf[:i]
        return events


def _append_to_buffer(buffer: str, char: str) -> str:
    if char in ("\x7f", "\x08"):
        return buffer[:-1] if buffer else buffer
    if char == "\x03":
        return ""
    if char.isprintable() or char == "\t":
        return buffer + char
    return buffer


async def _echo_input(websocket: WebSocket, char: str, *, had_buffer_char: bool) -> None:
    """Echo keystrokes to the client; xterm does not render local input without PTY echo."""
    if char in ("\x7f", "\x08"):
        if had_buffer_char:
            await websocket.send_text("\x08 \x08")
        return
    if char in ("\r", "\n"):
        await websocket.send_text("\r\n")
        return
    if char.isprintable() or char == "\t":
        await websocket.send_text(char)


async def run_console_session(websocket: WebSocket, *, user: AuthUser | None = None) -> None:
    loop = asyncio.get_running_loop()
    started_at = loop.time()
    timeout_seconds = settings.console_session_timeout_seconds
    line_buffer = ""
    input_parser = _ConsoleInputParser()
    current_proc: asyncio.subprocess.Process | None = None
    command_complete = asyncio.Event()
    command_complete.set()

    await websocket.send_text(WELCOME_DEMO if settings.demo_mode else WELCOME)
    await _send_prompt(websocket)

    try:
        while True:
            if loop.time() - started_at >= timeout_seconds:
                await websocket.close(code=4408, reason="Session timeout")
                break

            try:
                message = await asyncio.wait_for(websocket.receive(), timeout=1.0)
            except asyncio.TimeoutError:
                continue

            if message["type"] == "websocket.disconnect":
                break

            if message.get("type") != "websocket.receive":
                continue

            if "text" in message:
                text = message["text"]
                if text.startswith("{"):
                    try:
                        data = json.loads(text)
                        if data.get("type") == "resize":
                            continue
                    except (json.JSONDecodeError, TypeError, ValueError):
                        pass
                payload = text.encode()
            elif "bytes" in message:
                payload = message["bytes"]
            else:
                continue

            if not payload:
                continue

            for char in input_parser.feed(payload):
                if char == "\x03":
                    line_buffer = ""
                    if current_proc and current_proc.returncode is None:
                        current_proc.terminate()
                        try:
                            await asyncio.wait_for(current_proc.wait(), timeout=2)
                        except asyncio.TimeoutError:
                            current_proc.kill()
                            await current_proc.wait()
                        current_proc = None
                        command_complete.set()
                        await websocket.send_text("^C\r\n")
                    else:
                        await websocket.send_text("^C\r\n")
                        await _send_prompt(websocket)
                    continue

                if current_proc and current_proc.returncode is None:
                    continue

                if char in ("\r", "\n"):
                    if not command_complete.is_set():
                        continue
                    await _echo_input(websocket, char, had_buffer_char=bool(line_buffer))
                    command_line = line_buffer
                    line_buffer = ""
                    new_proc, new_complete = await _start_allowed_command(
                        websocket, command_line, user=user
                    )
                    if new_proc is not None and new_complete is not None:
                        current_proc = new_proc
                        command_complete = new_complete
                        command_complete.clear()
                    else:
                        current_proc = None
                        command_complete.set()
                    continue

                had_buffer_char = bool(line_buffer) and char in ("\x7f", "\x08")
                await _echo_input(websocket, char, had_buffer_char=had_buffer_char)
                line_buffer = _append_to_buffer(line_buffer, char)
    except WebSocketDisconnect:
        pass
    finally:
        if current_proc and current_proc.returncode is None:
            try:
                current_proc.terminate()
                await asyncio.wait_for(current_proc.wait(), timeout=2)
            except (asyncio.TimeoutError, ProcessLookupError):
                try:
                    current_proc.kill()
                except ProcessLookupError:
                    pass
