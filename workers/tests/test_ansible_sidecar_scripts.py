from pathlib import Path

from app.executors.ansible_exec import extract_script_module_refs, load_playbook_sidecar_files


def test_extract_script_module_refs_unique():
    content = """
- hosts: all
  tasks:
    - ansible.builtin.script: Ubuntu_22_scripts.sh
    - script: "helper.sh"
    - script: Ubuntu_22_scripts.sh
"""
    assert extract_script_module_refs(content) == ["Ubuntu_22_scripts.sh", "helper.sh"]


def test_load_playbook_sidecar_files(tmp_path: Path):
    script = tmp_path / "Ubuntu_22_scripts.sh"
    script.write_text("#!/bin/bash\necho RULE1= PASS: ok\n", encoding="utf-8")
    playbook = "- hosts: all\n  tasks:\n    - script: Ubuntu_22_scripts.sh\n"
    files = load_playbook_sidecar_files(playbook, tmp_path)
    assert list(files) == ["Ubuntu_22_scripts.sh"]
    assert b"RULE1=" in files["Ubuntu_22_scripts.sh"]


def test_load_playbook_sidecar_files_missing_package():
    playbook = "- hosts: all\n  tasks:\n    - script: missing.sh\n"
    assert load_playbook_sidecar_files(playbook, None) == {}
