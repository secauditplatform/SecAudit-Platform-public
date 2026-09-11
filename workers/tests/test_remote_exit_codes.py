from types import SimpleNamespace

import pytest

from app.executors.python_exec import _checked_output as check_python
from app.executors.ssh import _checked_output as check_ssh
from app.executors.winrm_exec import _checked_output as check_winrm


@pytest.mark.parametrize("checker", [check_ssh, check_python])
def test_nonzero_remote_exit_fails_even_with_stdout(checker):
    result = SimpleNamespace(exit_status=7, stdout="partial output", stderr="failure detail")
    with pytest.raises(RuntimeError) as exc:
        checker(result)
    message = str(exc.value)
    assert "code 7" in message
    assert "partial output" in message
    assert "failure detail" in message


def test_nonzero_winrm_exit_fails_even_with_stdout():
    result = SimpleNamespace(
        status_code=5,
        std_out=b"partial powershell output",
        std_err=b"powershell failure",
    )
    with pytest.raises(RuntimeError) as exc:
        check_winrm(result)
    assert "code 5" in str(exc.value)
    assert "partial powershell output" in str(exc.value)
    assert "powershell failure" in str(exc.value)


def test_only_explicit_success_codes_are_accepted():
    result = SimpleNamespace(exit_status=3, stdout="documented", stderr="")
    assert check_ssh(result, operation="test", success_codes=(0, 3)) == "documented"
