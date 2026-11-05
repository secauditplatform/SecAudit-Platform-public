"""Shared connectivity-check playbook content and legacy upgrade helpers."""

from __future__ import annotations

CONNECTIVITY_CHECK_CONTENT = """---
- name: SecAudit connectivity check
  hosts: all
  gather_facts: false
  tasks:
    - name: Check SSH command execution
      ansible.builtin.raw: echo secaudit-ok
      when: secaudit_connection | default('ssh') != 'winrm'
      changed_when: false

    - name: Ping target (WinRM/Windows)
      ansible.windows.win_ping:
      when: secaudit_connection | default('ssh') == 'winrm'
"""


def is_legacy_connectivity_check_content(content: str) -> bool:
    """True for built-in connectivity content that still needs the remote Python interpreter."""
    text = (content or "").replace("\r\n", "\n")
    return (
        "SecAudit connectivity check" in text
        and "ansible.builtin.ping:" in text
    )


def upgrade_connectivity_check_content(content: str) -> str:
    if is_legacy_connectivity_check_content(content):
        return CONNECTIVITY_CHECK_CONTENT
    return content
