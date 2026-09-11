"""Tests for built-in playbook templates."""

from app.services.playbook_templates import get_playbook_template


def test_connectivity_check_uses_win_ping_for_winrm_hosts():
    template = get_playbook_template("connectivity-check")
    assert template is not None
    content = template["content"]
    assert "ansible.builtin.ping:" in content
    assert "ansible.windows.win_ping:" in content
    assert "ansible_connection | default('ssh') != 'winrm'" in content
    assert "ansible_connection | default('ssh') == 'winrm'" in content
