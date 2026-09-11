from pathlib import Path
from types import SimpleNamespace

import pytest

from app.executors.ansible_exec import _ansible_collections_envvars, _run_playbook


def test_production_ansible_requires_stored_host_key(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("SSH_KNOWN_HOSTS_PATH", raising=False)
    with pytest.raises(ValueError, match="no stored SSH host key"):
        _run_playbook(
            "- hosts: all\n  tasks: []\n",
            [{"name": "server", "hostname": "server.example", "port": 22}],
            None,
            None,
            "ssh",
        )


def test_production_ansible_uses_per_run_known_hosts(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("SSH_KNOWN_HOSTS_PATH", raising=False)
    captured = {}

    def fake_run(**kwargs):
        captured.update(kwargs["envvars"])
        option = captured["ANSIBLE_SSH_ARGS"].split("UserKnownHostsFile=", 1)[1]
        captured["known_hosts"] = Path(option).read_text(encoding="utf-8")
        return SimpleNamespace(events=[], stdout=None, status="successful", rc=0)

    monkeypatch.setattr("app.executors.ansible_exec.ansible_runner.run", fake_run)
    output = _run_playbook(
        "- hosts: all\n  tasks: []\n",
        [
            {
                "name": "server",
                "hostname": "server.example",
                "port": 22,
                "ssh_known_hosts_entry": "server.example ssh-ed25519 AAAATEST",
            }
        ],
        None,
        None,
        "ssh",
    )

    assert captured["ANSIBLE_HOST_KEY_CHECKING"] == "True"
    assert captured["HOME"] != "/nonexistent"
    assert captured["ANSIBLE_LOCAL_TMP"].startswith(captured["HOME"])
    assert "server.example ssh-ed25519 AAAATEST" in captured["known_hosts"]
    assert "Playbook completed" in output


def test_ansible_runner_sets_writable_local_tmp(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    captured = {}

    def fake_run(**kwargs):
        captured.update(kwargs["envvars"])
        return SimpleNamespace(events=[], stdout=None, status="successful", rc=0)

    monkeypatch.setattr("app.executors.ansible_exec.ansible_runner.run", fake_run)
    _run_playbook(
        "- hosts: all\n  tasks: []\n",
        [{"name": "server", "hostname": "server.example", "port": 22}],
        None,
        None,
        "ssh",
    )

    assert captured["HOME"] != "/nonexistent"
    assert Path(captured["ANSIBLE_LOCAL_TMP"]).is_dir()
    assert captured["ANSIBLE_LOCAL_TMP"].startswith(captured["HOME"])


def test_ansible_collections_envvars_uses_shared_install(monkeypatch, tmp_path):
    collections = tmp_path / "collections"
    collections.mkdir()
    monkeypatch.setattr(
        "app.executors.ansible_exec._SHARED_COLLECTIONS_PATH",
        str(collections),
    )
    env = _ansible_collections_envvars()
    assert env["ANSIBLE_COLLECTIONS_PATH"] == str(collections)
    assert env["ANSIBLE_COLLECTIONS_PATHS"] == str(collections)
