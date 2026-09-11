from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from app.executors import winrm_exec


def test_iter_winrm_targets_defaults_to_http_then_https():
    assert winrm_exec.iter_winrm_targets(22) == [(5985, False), (5986, True)]
    assert winrm_exec.iter_winrm_targets(5985) == [(5985, False), (5986, True)]
    assert winrm_exec.iter_winrm_targets(5986) == [(5986, True), (5985, False)]


def test_iter_winrm_targets_discovery_ports_map_to_winrm():
    assert winrm_exec.normalize_winrm_port(445) == 5985
    assert winrm_exec.normalize_winrm_port(3389) == 5985
    assert winrm_exec.iter_winrm_targets(445) == [(5985, False), (5986, True)]


def test_iter_winrm_targets_custom_port_prefers_explicit_then_defaults():
    assert winrm_exec.iter_winrm_targets(55985) == [
        (55985, False),
        (5985, False),
        (5986, True),
    ]


@pytest.mark.parametrize(
    "message",
    [
        "HTTPConnectionPool(host='10.0.0.1', port=5985): Max retries exceeded",
        "Failed to establish a new connection: [Errno 111] Connection refused",
    ],
)
def test_is_connectivity_error(message: str):
    assert winrm_exec._is_connectivity_error(RuntimeError(message))


def test_is_connectivity_error_rejects_auth_failures():
    assert not winrm_exec._is_connectivity_error(RuntimeError("401 Unauthorized"))


def test_should_stage_large_powershell_scripts():
    small = 'Write-Output "ok"'
    large = "Write-Output '" + ("x" * 8000) + "'"
    assert not winrm_exec._should_stage_ps_script(small)
    assert winrm_exec._should_stage_ps_script(large)


def test_b64_upload_chunks_fit_encoded_command_limit():
    b64_name = "secaudit_Win11_scripts_911f348283bb8e22.b64"
    for append in (False, True):
        chunk_size = winrm_exec._max_b64_upload_chunk_chars(b64_name, append=append)
        assert chunk_size >= 300
        ps = winrm_exec._build_b64_chunk_command(b64_name, "A" * chunk_size, append=append)
        assert winrm_exec._encoded_ps_command_length(ps) <= winrm_exec.WINRM_MAX_INLINE_ENCODED_CHARS

    legacy_chunk = winrm_exec._build_b64_chunk_command(b64_name, "A" * 3000, append=False)
    assert winrm_exec._encoded_ps_command_length(legacy_chunk) > winrm_exec.WINRM_MAX_INLINE_ENCODED_CHARS


def test_temp_cleanup_command_uses_test_path_guard():
    command = winrm_exec._build_temp_cleanup_command("secaudit_demo.b64")
    assert "Test-Path -LiteralPath $p" in command
    assert "Remove-Item" in command
    assert "-ErrorAction SilentlyContinue" not in command


@patch("app.executors.winrm_exec.winrm.Session")
def test_run_script_over_winrm_stages_large_scripts(mock_session_cls, tmp_path: Path):
    script = tmp_path / "Win11_scripts.ps1"
    script.write_text("Write-Output '" + ("x" * 8000) + "'", encoding="utf-8")

    mock_session = MagicMock()
    mock_session.run_ps.return_value = SimpleNamespace(
        status_code=0,
        std_out=b"RULE1= PASS: ok",
        std_err=b"",
    )
    mock_session_cls.return_value = mock_session

    output = winrm_exec.run_script_over_winrm(
        hostname="win11.lab.local",
        port=5985,
        username="admin",
        password="secret",
        script_path=script,
    )

    assert output == "RULE1= PASS: ok"
    assert mock_session.run_ps.call_count > 1
    final_command = mock_session.run_ps.call_args_list[-1].args[0]
    assert "secaudit_Win11_scripts_" in final_command
    assert "& $scriptPath" in final_command


@patch("app.executors.winrm_exec.winrm.Session")
def test_run_script_over_winrm_passes_timeout_to_session_not_run_ps(mock_session_cls, tmp_path: Path):
    script = tmp_path / "check.ps1"
    script.write_text('Write-Output "RULE1= PASS: ok"', encoding="utf-8")

    mock_session = MagicMock()
    mock_session.run_ps.return_value = SimpleNamespace(
        status_code=0,
        std_out=b"RULE1= PASS: ok",
        std_err=b"",
    )
    mock_session_cls.return_value = mock_session

    output = winrm_exec.run_script_over_winrm(
        hostname="win11.lab.local",
        port=5985,
        username="admin",
        password="secret",
        script_path=script,
        timeout=120,
    )

    assert output == "RULE1= PASS: ok"
    mock_session_cls.assert_called_once()
    session_kwargs = mock_session_cls.call_args.kwargs
    assert session_kwargs["operation_timeout_sec"] == 120
    assert session_kwargs["read_timeout_sec"] == 150
    mock_session.run_ps.assert_called_once_with('Write-Output "RULE1= PASS: ok"')


@patch("app.executors.winrm_exec._run_winrm_once")
def test_run_script_over_winrm_falls_back_to_https(mock_run_once, tmp_path: Path):
    script = tmp_path / "check.ps1"
    script.write_text('Write-Output "RULE1= PASS: ok"', encoding="utf-8")

    mock_run_once.side_effect = [
        RuntimeError("HTTPConnectionPool(host='10.0.0.1', port=5985): Connection refused"),
        "RULE1= PASS: ok",
    ]

    output = winrm_exec.run_script_over_winrm(
        hostname="win11.lab.local",
        port=5985,
        username="admin",
        password="secret",
        script_path=script,
    )

    assert output == "RULE1= PASS: ok"
    assert mock_run_once.call_count == 2
    assert mock_run_once.call_args_list[0].kwargs["port"] == 5985
    assert mock_run_once.call_args_list[0].kwargs["use_ssl"] is False
    assert mock_run_once.call_args_list[1].kwargs["port"] == 5986
    assert mock_run_once.call_args_list[1].kwargs["use_ssl"] is True


@patch("app.executors.winrm_exec._run_winrm_once")
def test_run_script_over_winrm_reports_all_connectivity_failures(mock_run_once, tmp_path: Path):
    script = tmp_path / "check.ps1"
    script.write_text('Write-Output "RULE1= PASS: ok"', encoding="utf-8")
    mock_run_once.side_effect = [
        RuntimeError("HTTPConnectionPool(host='10.0.0.1', port=5985): Connection refused"),
        RuntimeError("HTTPConnectionPool(host='10.0.0.1', port=5986): Connection refused"),
    ]

    with pytest.raises(RuntimeError) as exc:
        winrm_exec.run_script_over_winrm(
            hostname="win11.lab.local",
            port=22,
            username="admin",
            password="secret",
            script_path=script,
        )

    assert "5985/http" in str(exc.value)
    assert "5986/https" in str(exc.value)
    assert mock_run_once.call_count == 2
