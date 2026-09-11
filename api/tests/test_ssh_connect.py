"""Tests for shared SSH connect kwargs."""

from secaudit_core.settings import SecAuditSettings
from secaudit_core.ssh_connect import build_ssh_connect_kwargs


def test_build_ssh_connect_kwargs_disables_known_hosts_in_dev():
    settings = SecAuditSettings(app_env="development", ssh_strict_host_key_checking=None)
    kwargs = build_ssh_connect_kwargs(
        host="10.0.0.1",
        port=22,
        username="root",
        password="secret",
        private_key=None,
        settings=settings,
    )
    assert kwargs["known_hosts"] is None
    assert kwargs["password"] == "secret"


def test_build_ssh_connect_kwargs_uses_known_hosts_in_production():
    settings = SecAuditSettings(
        app_env="production",
        ssh_known_hosts_path="/etc/ssh/ssh_known_hosts",
    )
    kwargs = build_ssh_connect_kwargs(
        host="10.0.0.1",
        port=22,
        username="root",
        password="secret",
        private_key=None,
        settings=settings,
    )
    assert kwargs["known_hosts"] == "/etc/ssh/ssh_known_hosts"


def test_build_ssh_connect_kwargs_uses_host_known_hosts_entry():
    settings = SecAuditSettings(app_env="development")
    entry = "host.example ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITestKeyMaterialHere1234567890abc"
    kwargs = build_ssh_connect_kwargs(
        host="host.example",
        port=22,
        username="root",
        password="secret",
        private_key=None,
        settings=settings,
        known_hosts_entry=entry,
    )
    # AsyncSSH treats str as a file path; per-host entries must be content
    # (SSHKnownHosts object or bytes), never a raw path-looking string.
    assert not isinstance(kwargs["known_hosts"], str)
    assert kwargs["known_hosts"] is not None


def test_build_ssh_connect_kwargs_requires_credentials():
    settings = SecAuditSettings(app_env="development")
    try:
        build_ssh_connect_kwargs(
            host="10.0.0.1",
            port=22,
            username="root",
            password=None,
            private_key=None,
            settings=settings,
        )
        assert False, "expected ValueError"
    except ValueError as exc:
        assert "SSH credential" in str(exc)
