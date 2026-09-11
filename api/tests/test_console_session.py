import json

import pytest
from fastapi.testclient import TestClient

from app.core.auth import create_local_token
from app.core.config import settings
from app.main import app
from app.services.console_command_policy import COMMAND_DENIED_MESSAGE
from app.services.console_session import _ConsoleInputParser, _append_to_buffer
from secaudit_core.enums import UserRole


@pytest.fixture(autouse=True)
def _console_embedded_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unit tests exercise in-process console; sandbox proxy is covered separately."""
    monkeypatch.setattr(settings, "console_sandbox_enabled", False)
    monkeypatch.setattr(settings, "console_enabled", True)
    monkeypatch.setattr(settings, "console_allow_in_production", True)


@pytest.mark.parametrize(
    ("buffer", "char", "expected"),
    [
        ("", "a", "a"),
        ("ab", "\x7f", "a"),
        ("", "\x7f", ""),
        ("", "\x03", ""),
        ("abc", "\x03", ""),
    ],
)
def test_append_to_buffer(buffer: str, char: str, expected: str) -> None:
    assert _append_to_buffer(buffer, char) == expected


@pytest.mark.parametrize(
    ("payload", "expected"),
    [
        (b"ping", ["p", "i", "n", "g"]),
        (b"\x1b[A", []),
        (b"\x1b[B\x1b[C\x1b[D", []),
        (b"ab\x1b[3~cd", ["a", "b", "c", "d"]),
        (b"echo\x1b[1;5H", ["e", "c", "h", "o"]),
        (b"\x1bOa", []),
        (b"\xe2\x98\x83", ["\u2603"]),
        (b"hi\r", ["h", "i", "\r"]),
        (b"\x7f", ["\x7f"]),
    ],
)
def test_console_input_parser(payload: bytes, expected: list[str]) -> None:
    parser = _ConsoleInputParser()
    assert parser.feed(payload) == expected


def test_console_input_parser_buffers_incomplete_escape() -> None:
    parser = _ConsoleInputParser()
    assert parser.feed(b"ab\x1b") == ["a", "b"]
    assert parser.feed(b"[Acd") == ["c", "d"]



def test_console_ws_ignores_arrow_key_sequences(client: TestClient) -> None:
    token = create_local_token("operator", [UserRole.OPERATOR.value])
    with client.websocket_connect("/api/v1/ws/console") as ws:
        ws.send_text(json.dumps({"type": "auth", "token": token}))
        ws.receive_text()
        ws.receive_text()

        ws.send_bytes(b"echo\x1b[A\x1b[B\x1b[C\x1b[D")

        echoed = ""
        for _ in range(4):
            echoed += ws.receive_text()

        assert echoed == "echo"
        assert "\x1b" not in echoed
        assert "[" not in echoed


def test_console_ws_echoes_keystrokes_and_runs_allowed_command(client: TestClient) -> None:
    token = create_local_token("operator", [UserRole.OPERATOR.value])
    with client.websocket_connect("/api/v1/ws/console") as ws:
        ws.send_text(json.dumps({"type": "auth", "token": token}))
        welcome = ws.receive_text()
        assert "SecAudit Console" in welcome
        prompt = ws.receive_text()
        assert "secaudit" in prompt

        ws.send_bytes(b"hostname")
        for char in "hostname":
            assert ws.receive_text() == char
        ws.send_bytes(b"\r")
        assert ws.receive_text() == "\r\n"

        output_chunks: list[str] = []
        while True:
            message = ws.receive()
            if "text" in message:
                chunk = message["text"]
            else:
                chunk = message["bytes"].decode("utf-8", errors="replace")
            output_chunks.append(chunk)
            if chunk.endswith("$ "):
                break

        output = "".join(output_chunks)
        assert "Command not allowed" not in output


def test_console_ws_denies_blocked_command(client: TestClient) -> None:
    token = create_local_token("operator", [UserRole.OPERATOR.value])
    with client.websocket_connect("/api/v1/ws/console") as ws:
        ws.send_text(json.dumps({"type": "auth", "token": token}))
        ws.receive_text()
        ws.receive_text()

        ws.send_bytes(b"rm -rf /\r")

        messages: list[str] = []
        while True:
            chunk = ws.receive_text()
            messages.append(chunk)
            if COMMAND_DENIED_MESSAGE in chunk:
                break

        echoed = "".join(messages)
        assert "rm -rf /" in echoed
        assert COMMAND_DENIED_MESSAGE in echoed
        assert ws.receive_text().endswith("$ ")
