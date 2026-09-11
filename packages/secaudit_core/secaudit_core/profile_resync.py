"""Helpers for re-importing profile packages without breaking remediation job links."""

from __future__ import annotations

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session

from secaudit_core.enums import ScriptKind
from secaudit_core.models import CheckScript, InterpreterRule, RemediationJob, Rule


def capture_remediation_script_links(session: Session, profile_id: int) -> dict[int, str]:
    """Map remediation_job.id -> check_script.script_file before script rows are replaced."""
    rows = session.execute(
        select(RemediationJob.id, CheckScript.script_file)
        .join(CheckScript, RemediationJob.remediation_script_id == CheckScript.id)
        .where(RemediationJob.profile_id == profile_id)
    ).all()
    return {job_id: script_file for job_id, script_file in rows}


def detach_remediation_script_links(session: Session, profile_id: int) -> None:
    """Clear FK references so check_scripts can be deleted during profile re-import."""
    session.execute(
        update(RemediationJob)
        .where(RemediationJob.profile_id == profile_id)
        .where(RemediationJob.remediation_script_id.isnot(None))
        .values(remediation_script_id=None)
    )


def delete_profile_rules_and_scripts(session: Session, profile_id: int) -> None:
    script_ids = list(
        session.scalars(select(CheckScript.id).where(CheckScript.profile_id == profile_id)).all()
    )
    if script_ids:
        session.execute(delete(InterpreterRule).where(InterpreterRule.check_script_id.in_(script_ids)))
    session.execute(delete(CheckScript).where(CheckScript.profile_id == profile_id))
    session.execute(delete(Rule).where(Rule.profile_id == profile_id))


def restore_remediation_script_links(
    session: Session,
    profile_id: int,
    job_script_files: dict[int, str],
) -> None:
    """Re-link remediation jobs to newly imported scripts matched by script_file."""
    if not job_script_files:
        return

    scripts = session.scalars(
        select(CheckScript).where(
            CheckScript.profile_id == profile_id,
            CheckScript.script_kind == ScriptKind.REMEDIATION,
        )
    ).all()
    by_file = {script.script_file: script.id for script in scripts}
    for job_id, script_file in job_script_files.items():
        new_id = by_file.get(script_file)
        if new_id is None:
            continue
        session.execute(
            update(RemediationJob).where(RemediationJob.id == job_id).values(remediation_script_id=new_id)
        )
