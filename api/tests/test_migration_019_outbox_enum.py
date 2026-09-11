"""Migration 019 must rename outboxstatus in place and preserve task_outbox rows."""

from __future__ import annotations

import os
import uuid
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError


def _postgres_url(database: str) -> str:
    user = os.environ.get("POSTGRES_USER", "secaudit")
    password = os.environ.get("POSTGRES_PASSWORD", "secaudit_dev")
    host = os.environ.get("POSTGRES_HOST", "localhost")
    port = os.environ.get("POSTGRES_PORT", "5432")
    return f"postgresql://{user}:{password}@{host}:{port}/{database}"


@pytest.fixture
def disposable_pg_database():
    """Create an isolated Postgres DB for migration upgrade checks."""
    admin = create_engine(_postgres_url("postgres"), isolation_level="AUTOCOMMIT")
    db_name = f"secaudit_mig019_{uuid.uuid4().hex[:8]}"
    try:
        with admin.connect() as conn:
            conn.execute(text(f'CREATE DATABASE "{db_name}"'))
    except OperationalError as exc:
        admin.dispose()
        pytest.skip(f"PostgreSQL is not available for migration tests: {exc}")

    engine = create_engine(_postgres_url(db_name))
    try:
        yield engine, db_name
    finally:
        engine.dispose()
        with admin.connect() as conn:
            conn.execute(
                text(
                    """
                    SELECT pg_terminate_backend(pid)
                    FROM pg_stat_activity
                    WHERE datname = :db_name AND pid <> pg_backend_pid()
                    """
                ),
                {"db_name": db_name},
            )
            conn.execute(text(f'DROP DATABASE IF EXISTS "{db_name}"'))
        admin.dispose()


def test_019_preserves_populated_outbox_rows(disposable_pg_database, monkeypatch):
    engine, db_name = disposable_pg_database

    with engine.begin() as conn:
        conn.execute(text("CREATE TYPE outboxstatus AS ENUM ('pending', 'sent', 'failed')"))
        conn.execute(
            text(
                """
                CREATE TABLE task_outbox (
                    id SERIAL PRIMARY KEY,
                    task_name VARCHAR(256) NOT NULL,
                    args_json TEXT NOT NULL,
                    kwargs_json TEXT,
                    queue VARCHAR(64) NOT NULL,
                    status outboxstatus NOT NULL DEFAULT 'pending',
                    callback_kind VARCHAR(32),
                    callback_ref_id INTEGER,
                    celery_task_id VARCHAR(128),
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                    sent_at TIMESTAMPTZ
                )
                """
            )
        )
        conn.execute(
            text(
                "CREATE INDEX ix_task_outbox_status_created ON task_outbox (status, created_at)"
            )
        )
        inserted = conn.execute(
            text(
                """
                INSERT INTO task_outbox (id, task_name, args_json, queue, status, celery_task_id)
                VALUES
                    (11, 'task.pending', '[]', 'compliance', 'pending', 'outbox-11'),
                    (22, 'task.sent', '[]', 'compliance', 'sent', 'outbox-22'),
                    (33, 'task.failed', '[]', 'maintenance', 'failed', 'outbox-33')
                RETURNING id, status::text
                """
            )
        ).all()
        assert [(row.id, row.status) for row in inserted] == [
            (11, "pending"),
            (22, "sent"),
            (33, "failed"),
        ]
        conn.execute(text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL)"))
        conn.execute(
            text("INSERT INTO alembic_version (version_num) VALUES ('018_task_outbox')")
        )

    monkeypatch.setenv("POSTGRES_DB", db_name)
    api_root = Path(__file__).resolve().parents[1]
    cfg = Config(str(api_root / "alembic.ini"))
    cfg.set_main_option("script_location", str(api_root / "alembic"))
    cfg.set_main_option("sqlalchemy.url", _postgres_url(db_name))
    command.upgrade(cfg, "019_fix_outboxstatus_enum_case")

    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT id, status::text, celery_task_id FROM task_outbox ORDER BY id")
        ).all()
        labels = conn.execute(
            text(
                """
                SELECT e.enumlabel
                FROM pg_enum e
                JOIN pg_type t ON e.enumtypid = t.oid
                WHERE t.typname = 'outboxstatus'
                ORDER BY e.enumsortorder
                """
            )
        ).scalars().all()
        version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()

    assert version == "019_fix_outboxstatus_enum_case"
    assert labels == ["PENDING", "SENT", "FAILED"]
    assert len(rows) == 3
    assert [(row.id, row.status, row.celery_task_id) for row in rows] == [
        (11, "PENDING", "outbox-11"),
        (22, "SENT", "outbox-22"),
        (33, "FAILED", "outbox-33"),
    ]
