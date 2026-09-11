from secaudit_core.connectivity_playbook import (
    CONNECTIVITY_CHECK_CONTENT,
    is_legacy_connectivity_check_content,
    upgrade_connectivity_check_content,
)

LEGACY_CONTENT = """---
- name: SecAudit connectivity check
  hosts: all
  gather_facts: false
  tasks:
    - name: Ping target
      ansible.builtin.ping:
"""


def test_is_legacy_connectivity_check_content():
    assert is_legacy_connectivity_check_content(LEGACY_CONTENT)
    assert not is_legacy_connectivity_check_content(CONNECTIVITY_CHECK_CONTENT)
    assert not is_legacy_connectivity_check_content("---\n- hosts: all\n")


def test_upgrade_connectivity_check_content():
    assert upgrade_connectivity_check_content(LEGACY_CONTENT) == CONNECTIVITY_CHECK_CONTENT
    assert upgrade_connectivity_check_content(CONNECTIVITY_CHECK_CONTENT) == CONNECTIVITY_CHECK_CONTENT
