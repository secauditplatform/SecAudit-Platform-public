"""Playbook YAML/Ansible syntax validation helpers."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

import yaml

from app.schemas import PlaybookValidateResponse


def _ansible_env(work_dir: Path) -> dict[str, str]:
    """Build env so ansible-playbook works as non-root (HOME=/nonexistent in containers)."""
    local_tmp = work_dir / "ansible-local"
    local_tmp.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["HOME"] = str(work_dir)
    env["ANSIBLE_LOCAL_TMP"] = str(local_tmp)
    env["ANSIBLE_HOST_KEY_CHECKING"] = "False"
    env["ANSIBLE_RETRY_FILES_ENABLED"] = "False"
    env["ANSIBLE_DEPRECATION_WARNINGS"] = "False"
    env["ANSIBLE_DISPLAY_SKIPPED_HOSTS"] = "False"
    # Prefer shared collection path from image build when present.
    collections = Path("/usr/share/ansible/collections")
    if collections.is_dir():
        env["ANSIBLE_COLLECTIONS_PATH"] = str(collections)
        env["ANSIBLE_COLLECTIONS_PATHS"] = str(collections)
    return env


def _format_ansible_output(stdout: str, stderr: str) -> str:
    text = "\n".join(part.strip() for part in (stderr, stdout) if part and part.strip()).strip()
    return text or "ansible-playbook syntax check failed"


def validate_playbook_content(content: str) -> PlaybookValidateResponse:
    """Validate playbook content: YAML parse + ansible-playbook --syntax-check."""
    stripped = (content or "").strip()
    if not stripped:
        return PlaybookValidateResponse(valid=False, message="Playbook content is empty")

    try:
        loaded = yaml.safe_load(stripped)
    except yaml.YAMLError as exc:
        return PlaybookValidateResponse(valid=False, message=f"Invalid YAML: {exc}")

    if loaded is None:
        return PlaybookValidateResponse(valid=False, message="Playbook content is empty")
    if not isinstance(loaded, (list, dict)):
        return PlaybookValidateResponse(
            valid=False,
            message="Playbook YAML must be a list of plays or a mapping",
        )

    with tempfile.TemporaryDirectory(prefix="secaudit-pb-validate-") as tmp:
        work_dir = Path(tmp)
        path = work_dir / "playbook.yml"
        path.write_text(stripped, encoding="utf-8")
        env = _ansible_env(work_dir)
        try:
            result = subprocess.run(
                [
                    "ansible-playbook",
                    "--syntax-check",
                    "-i",
                    "localhost,",
                    str(path),
                ],
                capture_output=True,
                text=True,
                timeout=30,
                env=env,
                cwd=str(work_dir),
            )
        except FileNotFoundError:
            return PlaybookValidateResponse(
                valid=True,
                message="YAML OK (ansible-playbook not installed; Ansible syntax check skipped)",
            )
        except subprocess.TimeoutExpired:
            return PlaybookValidateResponse(
                valid=False,
                message="ansible-playbook syntax check timed out",
            )

        if result.returncode == 0:
            message = (result.stdout or "").strip() or "Syntax OK"
            return PlaybookValidateResponse(valid=True, message=message)

        return PlaybookValidateResponse(
            valid=False,
            message=_format_ansible_output(result.stdout or "", result.stderr or ""),
        )
