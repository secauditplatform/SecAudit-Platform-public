"""Shared connectivity-check playbook content and legacy upgrade helpers."""

from __future__ import annotations

CONNECTIVITY_CHECK_CONTENT = """---
- name: SecAudit connectivity check
  hosts: all
  gather_facts: false
  tasks:
    - name: Ping target (SSH/Linux)
      ansible.builtin.ping:
      when: ansible_connection | default('ssh') != 'winrm'

    - name: Ping target (WinRM/Windows)
      ansible.windows.win_ping:
      when: ansible_connection | default('ssh') == 'winrm'
"""


def is_legacy_connectivity_check_content(content: str) -> bool:
    """True when playbook still uses ansible.builtin.ping for all hosts."""
    text = (content or "").replace("\r\n", "\n")
    if "SecAudit connectivity check" not in text:
        return False
    if "ansible.windows.win_ping:" in text:
        return False
    return "ansible.builtin.ping:" in text


def upgrade_connectivity_check_content(content: str) -> str:
    if is_legacy_connectivity_check_content(content):
        return CONNECTIVITY_CHECK_CONTENT
    return content
