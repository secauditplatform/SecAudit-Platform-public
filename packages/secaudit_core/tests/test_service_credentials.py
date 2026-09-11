"""Tests for service-layer credential env injection."""

from types import SimpleNamespace

import shlex

from secaudit_core.enums import CategoryType
from secaudit_core.service_credentials import (
    profile_uses_service_credentials,
    service_env_from_credential,
    service_script_cli_suffix,
    shell_export_prefix,
    powershell_env_prefix,
)


class _FakeCred:
    def __init__(
        self,
        *,
        service_username: str | None = None,
        encrypted_service_secret: str | None = None,
    ) -> None:
        self.service_username = service_username
        self.encrypted_service_secret = encrypted_service_secret


def test_profile_uses_service_credentials():
    assert profile_uses_service_credentials(CategoryType.OS) is False
    assert profile_uses_service_credentials(CategoryType.DATABASE) is True
    assert profile_uses_service_credentials(CategoryType.MIDDLEWARE) is True
    assert profile_uses_service_credentials(None) is False


def test_service_env_from_credential_empty():
    assert service_env_from_credential(_FakeCred()) == {}


def test_service_env_from_credential_decrypts(monkeypatch):
    cred = _FakeCred(service_username="dbadmin", encrypted_service_secret="enc")
    monkeypatch.setattr(
        "secaudit_core.service_credentials.decrypt_credential_service_secret",
        lambda c, settings=None: "s3cret",
    )
    env = service_env_from_credential(cred)
    assert env["SECAUDIT_SERVICE_USER"] == "dbadmin"
    assert env["DB_USER"] == "dbadmin"
    assert env["SECAUDIT_SERVICE_PASS"] == "s3cret"
    assert env["DB_PASS"] == "s3cret"


def test_service_script_cli_suffix_builds_flags():
    password = "p'a$s"
    suffix = service_script_cli_suffix({"DB_USER": "postgres", "DB_PASS": password})
    expected = (
        f" -software_user {shlex.quote('postgres')} "
        f"-software_password {shlex.quote(password)}"
    )
    assert suffix == expected


def test_shell_export_prefix_quotes_values():
    prefix = shell_export_prefix({"DB_USER": "admin", "DB_PASS": "p'a$s"})
    assert "export DB_USER=admin" in prefix
    assert "DB_PASS=" in prefix
    assert prefix.endswith("; ")


def test_powershell_env_prefix_escapes_quotes():
    prefix = powershell_env_prefix({"SERVICE_PASS": "x'y"})
    assert "$env:SERVICE_PASS = 'x''y'" in prefix
