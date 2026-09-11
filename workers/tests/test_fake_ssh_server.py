import socket

from secaudit_core.settings import SecAuditSettings
from secaudit_core.ssh_connect import build_ssh_connect_kwargs

from fake_ssh_server import FakeSshServer


def test_fake_ssh_server_accepts_tcp_connection():
    server = FakeSshServer()
    try:
        with socket.create_connection(("127.0.0.1", server.port), timeout=2) as sock:
            banner = sock.recv(64)
        assert banner.startswith(b"SSH-2.0-FakeSecAudit")
    finally:
        server.close()


def test_build_ssh_connect_kwargs_for_fake_host():
    settings = SecAuditSettings(app_env="development")
    kwargs = build_ssh_connect_kwargs(
        host="127.0.0.1",
        port=2222,
        username="ops",
        password="secret",
        private_key=None,
        settings=settings,
    )
    assert kwargs["host"] == "127.0.0.1"
    assert kwargs["port"] == 2222
    assert kwargs["known_hosts"] is None
