"""Tests for profile re-import helpers (remediation script FK safety)."""

from pathlib import Path

import json
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from secaudit_core.enums import ExecutionType, ScriptKind
from secaudit_core.models import Base, Category, CategoryType, CheckScript, RemediationJob
from secaudit_core.profile_packages import load_profile_package
from secaudit_core.profiles_sync import import_package_from_mount
from secaudit_core.settings import SecAuditSettings


def _write_fstek_like_package(root: Path) -> Path:
    package_dir = root / "fstek_pkg"
    package_dir.mkdir(parents=True)
    (package_dir / "description.json").write_text(
        """{
  "profile_name": "FSTEK Linux",
  "version": "1.0",
  "os": {"name": "Linux", "vendor": "*", "version": "*"},
  "profile_rules": "profile_rules.json"
}""",
        encoding="utf-8",
    )
    (package_dir / "profile_rules.json").write_text(
        json.dumps(
            {
                "version": 1,
                "format": "secaudit.profile_rules",
                "rules": [
                    {
                        "num": "1",
                        "title": "summary",
                        "explanation": "desc",
                        "criticality": "LOW",
                        "check_script": "FSTEK_linux_scripts",
                        "requirement_id": "RULE0001",
                        "match_pattern": "RULE1=(.*)",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    (package_dir / "FSTEK_linux_scripts.sh").write_text("#!/bin/bash\necho RULE1=PASS:", encoding="utf-8")
    (package_dir / "FSTEK_linux_remediation.sh").write_text("#!/bin/bash\necho fix", encoding="utf-8")
    return package_dir


@pytest.fixture
def sync_db(tmp_path: Path):
    db_path = tmp_path / "resync.db"
    engine = create_engine(f"sqlite:///{db_path}")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    with SessionLocal() as session:
        session.add(
            Category(
                name="Linux Platform",
                slug="linux-platform",
                category_type=CategoryType.OS,
            )
        )
        session.commit()
    yield SessionLocal
    engine.dispose()


def test_import_package_from_mount_preserves_remediation_job_script_link(tmp_path, sync_db) -> None:
    SessionLocal = sync_db
    with SessionLocal() as db:
        settings = SecAuditSettings(
            profiles_storage_path=str(tmp_path / "storage"),
            profiles_path=str(tmp_path / "mount"),
        )
        package_dir = _write_fstek_like_package(tmp_path / "mount")

        profile = import_package_from_mount(db, settings, package_dir)
        db.flush()

        remediation = CheckScript(
            profile_id=profile.id,
            name="FSTEK_linux_remediation",
            execution_type=ExecutionType.SSH,
            script_file="FSTEK_linux_remediation.sh",
            script_kind=ScriptKind.REMEDIATION,
        )
        db.add(remediation)
        db.flush()

        job = RemediationJob(
            name="fix job",
            profile_id=profile.id,
            remediation_script_id=remediation.id,
            execution_type=ExecutionType.SSH,
        )
        db.add(job)
        db.flush()
        job_id = job.id
        old_script_id = remediation.id

        package_dir.joinpath("description.json").write_text(
            package_dir.joinpath("description.json").read_text(encoding="utf-8").replace(
                '"version": "1.0"', '"version": "1.1"'
            ),
            encoding="utf-8",
        )

        updated = import_package_from_mount(db, settings, package_dir, replace_existing=True)
        db.commit()

        assert updated.version == "1.1"
        refreshed_job = db.get(RemediationJob, job_id)
        assert refreshed_job is not None
        assert refreshed_job.remediation_script_id is not None
        assert refreshed_job.remediation_script_id != old_script_id

        script = db.get(CheckScript, refreshed_job.remediation_script_id)
        assert script is not None
        assert script.script_file == "FSTEK_linux_remediation.sh"

def test_fstek_source_package_loads_from_repo() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    package_dir = repo_root / "profiles/Linux Platform/FSTEK_AI/FSTEK_AI_CRE"
    if not package_dir.is_dir():
        pytest.skip("FSTEK profile package not present")
    package = load_profile_package(package_dir)
    assert package["profile"]["profile_name"] == "FSTEK Linux"
