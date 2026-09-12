"""Tests for Ansible playbook worker-isolation policy."""

from __future__ import annotations

import pytest
import yaml

from secaudit_core.playbook_policy import validate_playbook_policy, validate_playbook_text


def _load(text: str):
    return yaml.safe_load(text)


def test_allows_remote_shell_playbook():
    loaded = _load(
        """
- hosts: all
  tasks:
    - name: check
      ansible.builtin.shell: echo ok
"""
    )
    validate_playbook_policy(loaded)


def test_allows_localhost_delegate_ping_command():
    loaded = _load(
        """
- hosts: all
  gather_facts: false
  tasks:
    - name: ICMP ping
      ansible.builtin.command:
        argv:
          - ping
          - "-c"
          - "1"
          - "-W"
          - "2"
          - "{{ ansible_host }}"
      delegate_to: localhost
"""
    )
    validate_playbook_policy(loaded)


def test_rejects_connection_local():
    loaded = _load(
        """
- hosts: all
  connection: local
  tasks:
    - debug:
        msg: hi
"""
    )
    with pytest.raises(ValueError, match="connection"):
        validate_playbook_policy(loaded)


def test_rejects_connection_local_fqcn():
    loaded = _load(
        """
- hosts: all
  connection: ansible.builtin.local
  tasks:
    - debug:
        msg: hi
"""
    )
    with pytest.raises(ValueError, match="connection"):
        validate_playbook_policy(loaded)


def test_rejects_ansible_connection_via_vars():
    loaded = _load(
        """
- hosts: all
  vars:
    ansible_connection: local
  tasks:
    - debug:
        msg: hi
"""
    )
    with pytest.raises(ValueError, match="ansible_connection"):
        validate_playbook_policy(loaded)


def test_rejects_local_action():
    loaded = _load(
        """
- hosts: all
  tasks:
    - local_action: shell id
"""
    )
    with pytest.raises(ValueError, match="local_action"):
        validate_playbook_policy(loaded)


def test_rejects_localhost_shell():
    loaded = _load(
        """
- hosts: all
  tasks:
    - name: pwn
      ansible.builtin.shell: id
      delegate_to: localhost
"""
    )
    with pytest.raises(ValueError, match="delegate_to localhost"):
        validate_playbook_policy(loaded)


def test_rejects_hosts_localhost():
    loaded = _load(
        """
- hosts: localhost
  tasks:
    - debug:
        msg: hi
"""
    )
    with pytest.raises(ValueError, match="localhost"):
        validate_playbook_policy(loaded)


def test_rejects_hosts_mixed_localhost():
    loaded = _load(
        """
- hosts: localhost,all
  tasks:
    - debug:
        msg: hi
"""
    )
    with pytest.raises(ValueError, match="localhost"):
        validate_playbook_policy(loaded)


def test_rejects_import_tasks():
    loaded = _load(
        """
- hosts: all
  tasks:
    - ansible.builtin.import_tasks: evil.yml
"""
    )
    with pytest.raises(ValueError, match="not allowed"):
        validate_playbook_policy(loaded)


def test_rejects_jinja_lookup_plugin():
    loaded = _load(
        """
- hosts: all
  tasks:
    - ansible.builtin.debug:
        msg: "{{ lookup('pipe', 'id') }}"
"""
    )
    with pytest.raises(ValueError, match="lookup"):
        validate_playbook_policy(loaded)


def test_rejects_jinja_query_in_raw_text():
    with pytest.raises(ValueError, match="lookup/query"):
        validate_playbook_text("- hosts: all\n  tasks: [{debug: {msg: \"{{ query('env', 'HOME') }}\"}}]")
