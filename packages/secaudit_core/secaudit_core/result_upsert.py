"""Dialect-aware idempotent writes for run result rows."""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from secaudit_core.models import CheckResult, RemediationResult


def upsert_check_result(
    db: Session,
    *,
    job_run_id: int,
    host_id: int,
    rule_tech_name: str,
    status,
    message: str | None,
    raw_output: str | None = None,
) -> None:
    values = {
        "job_run_id": job_run_id,
        "host_id": host_id,
        "rule_tech_name": rule_tech_name,
        "status": status,
        "message": message,
        "raw_output": raw_output,
    }
    key = ("job_run_id", "host_id", "rule_tech_name")
    updates = {
        "status": status,
        "message": message,
        "raw_output": raw_output,
    }
    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        db.execute(
            pg_insert(CheckResult)
            .values(**values)
            .on_conflict_do_update(
                constraint="uq_check_result_run_host_rule",
                set_=updates,
            )
        )
        return
    if dialect == "sqlite":
        db.execute(
            sqlite_insert(CheckResult)
            .values(**values)
            .on_conflict_do_update(index_elements=list(key), set_=updates)
        )
        return
    existing = db.execute(
        select(CheckResult).where(
            CheckResult.job_run_id == job_run_id,
            CheckResult.host_id == host_id,
            CheckResult.rule_tech_name == rule_tech_name,
        )
    ).scalar_one_or_none()
    if existing is None:
        db.add(CheckResult(**values))
    else:
        for field, value in updates.items():
            setattr(existing, field, value)


def upsert_remediation_result(
    db: Session,
    *,
    remediation_run_id: int,
    host_id: int,
    script_name: str,
    status,
    message: str | None,
    raw_output: str | None,
) -> None:
    values = {
        "remediation_run_id": remediation_run_id,
        "host_id": host_id,
        "script_name": script_name,
        "status": status,
        "message": message,
        "raw_output": raw_output,
    }
    key = ("remediation_run_id", "host_id", "script_name")
    updates = {
        "status": status,
        "message": message,
        "raw_output": raw_output,
    }
    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        statement = (
            pg_insert(RemediationResult)
            .values(**values)
            .on_conflict_do_update(
                constraint="uq_remediation_result_run_host_script",
                set_=updates,
            )
        )
        db.execute(statement)
        return
    if dialect == "sqlite":
        statement = (
            sqlite_insert(RemediationResult)
            .values(**values)
            .on_conflict_do_update(index_elements=list(key), set_=updates)
        )
        db.execute(statement)
        return

    existing = db.execute(
        select(RemediationResult).where(
            RemediationResult.remediation_run_id == remediation_run_id,
            RemediationResult.host_id == host_id,
            RemediationResult.script_name == script_name,
        )
    ).scalar_one_or_none()
    if existing is None:
        db.add(RemediationResult(**values))
    else:
        for field, value in updates.items():
            setattr(existing, field, value)
