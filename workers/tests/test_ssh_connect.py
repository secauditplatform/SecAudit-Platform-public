from secaudit_core.settings import SecAuditSettings
from secaudit_core.ssh_connect import build_ssh_connect_kwargs


def test_python_exec_uses_strict_host_key_policy_in_production():
    settings = SecAuditSettings(app_env="production", ssh_known_hosts_path="/known_hosts")
    kwargs = build_ssh_connect_kwargs(
        host="host.example",
        port=22,
        username="ops",
        password="x",
        private_key=None,
        settings=settings,
    )
    assert kwargs["known_hosts"] == "/known_hosts"
