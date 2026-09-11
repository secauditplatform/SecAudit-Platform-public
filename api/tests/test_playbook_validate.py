"""Tests for playbook YAML / Ansible syntax validation."""

from __future__ import annotations

from types import SimpleNamespace

from app.services import playbook_validate


def test_validate_rejects_empty_content():
    result = playbook_validate.validate_playbook_content("   ")
    assert result.valid is False
    assert "empty" in result.message.lower()


def test_validate_rejects_invalid_yaml():
    result = playbook_validate.validate_playbook_content("hosts: [\n  - broken")
    assert result.valid is False
    assert "Invalid YAML" in result.message


def test_validate_rejects_non_playbook_scalar():
    result = playbook_validate.validate_playbook_content("just-a-string")
    assert result.valid is False
    assert "list of plays" in result.message.lower() or "mapping" in result.message.lower()


def test_validate_uses_writable_home_and_inventory(monkeypatch, tmp_path):
    calls: list[dict] = []

    def fake_run(cmd, **kwargs):
        calls.append({"cmd": cmd, "env": kwargs.get("env"), "cwd": kwargs.get("cwd")})
        return SimpleNamespace(returncode=0, stdout="playbook: ok\n", stderr="")

    monkeypatch.setattr(playbook_validate.subprocess, "run", fake_run)

    content = """
- name: Demo
  hosts: all
  gather_facts: false
  tasks:
    - ansible.builtin.debug:
        msg: hi
"""
    result = playbook_validate.validate_playbook_content(content)
    assert result.valid is True
    assert "ok" in result.message.lower() or "Syntax OK" in result.message
    assert calls, "ansible-playbook should be invoked"
    cmd = calls[0]["cmd"]
    assert cmd[0] == "ansible-playbook"
    assert "--syntax-check" in cmd
    assert "-i" in cmd
    assert "localhost," in cmd
    env = calls[0]["env"]
    assert env["HOME"]
    assert env["HOME"] != "/nonexistent"
    assert env["ANSIBLE_LOCAL_TMP"].startswith(env["HOME"])


def test_validate_returns_ansible_stderr_on_failure(monkeypatch):
    def fake_run(_cmd, **_kwargs):
        return SimpleNamespace(
            returncode=2,
            stdout="",
            stderr="ERROR! the playbook file is empty",
        )

    monkeypatch.setattr(playbook_validate.subprocess, "run", fake_run)
    result = playbook_validate.validate_playbook_content(
        "- name: x\n  hosts: all\n  tasks: []\n"
    )
    assert result.valid is False
    assert "ERROR!" in result.message


def test_validate_skips_when_ansible_missing(monkeypatch):
    def fake_run(_cmd, **_kwargs):
        raise FileNotFoundError("ansible-playbook")

    monkeypatch.setattr(playbook_validate.subprocess, "run", fake_run)
    result = playbook_validate.validate_playbook_content(
        "- name: x\n  hosts: all\n  tasks: []\n"
    )
    assert result.valid is True
    assert "skipped" in result.message.lower()
