"""PostgreSQL-only locking and migration constraint checks.

Set SECAUDIT_POSTGRES_TEST_URL to a migrated disposable/test database.
"""

import os

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError, IntegrityError


@pytest.fixture(scope="module")
def pg_engine():
    url = os.getenv("SECAUDIT_POSTGRES_TEST_URL")
    if not url:
        pytest.skip("SECAUDIT_POSTGRES_TEST_URL is not configured")
    engine = create_engine(url)
    yield engine
    engine.dispose()


def test_skip_locked_excludes_an_active_outbox_claim(pg_engine):
    with pg_engine.begin() as setup:
        outbox_id = setup.execute(
            text(
                """
                INSERT INTO task_outbox (
                    task_name, args_json, queue, status, celery_task_id
                ) VALUES (
                    'test.dispatch', '[]', 'maintenance', 'PENDING',
                    'postgres-lock-test-' || txid_current()::text
                )
                RETURNING id
                """
            )
        ).scalar_one()

    try:
        with pg_engine.connect() as first, pg_engine.connect() as second:
            first_tx = first.begin()
            second_tx = second.begin()
            assert (
                first.execute(
                    text(
                        "SELECT id FROM task_outbox WHERE id=:id FOR UPDATE"
                    ),
                    {"id": outbox_id},
                ).scalar_one()
                == outbox_id
            )
            assert (
                second.execute(
                    text(
                        """
                        SELECT id FROM task_outbox
                        WHERE id=:id FOR UPDATE SKIP LOCKED
                        """
                    ),
                    {"id": outbox_id},
                ).scalar_one_or_none()
                is None
            )
            second_tx.rollback()
            first_tx.rollback()
    finally:
        with pg_engine.begin() as cleanup:
            cleanup.execute(
                text("DELETE FROM task_outbox WHERE id=:id"), {"id": outbox_id}
            )


def test_terminal_trigger_and_result_constraint(pg_engine):
    with pg_engine.connect() as connection:
        transaction = connection.begin()
        job_id = connection.execute(
            text(
                """
                INSERT INTO jobs (
                    name, is_scheduled, is_active, enforce_host_owner_scope
                ) VALUES ('pg-state-test', false, true, false)
                RETURNING id
                """
            )
        ).scalar_one()
        run_id = connection.execute(
            text(
                """
                INSERT INTO job_runs (job_id, status)
                VALUES (:job_id, 'PENDING') RETURNING id
                """
            ),
            {"job_id": job_id},
        ).scalar_one()
        host_id = connection.execute(
            text(
                """
                INSERT INTO hosts (name, hostname, port, is_active)
                VALUES ('pg-state-host', '192.0.2.250', 22, true) RETURNING id
                """
            )
        ).scalar_one()

        connection.execute(
            text("UPDATE job_runs SET status='FAILED' WHERE id=:id"),
            {"id": run_id},
        )
        savepoint = connection.begin_nested()
        with pytest.raises(DBAPIError):
            connection.execute(
                text("UPDATE job_runs SET status='RUNNING' WHERE id=:id"),
                {"id": run_id},
            )
        savepoint.rollback()

        connection.execute(
            text(
                """
                INSERT INTO check_results (
                    job_run_id, host_id, rule_tech_name, status
                ) VALUES (:run_id, :host_id, 'same-rule', 'PASS')
                """
            ),
            {"run_id": run_id, "host_id": host_id},
        )
        savepoint = connection.begin_nested()
        with pytest.raises(IntegrityError):
            connection.execute(
                text(
                    """
                    INSERT INTO check_results (
                        job_run_id, host_id, rule_tech_name, status
                    ) VALUES (:run_id, :host_id, 'same-rule', 'FAIL')
                    """
                ),
                {"run_id": run_id, "host_id": host_id},
            )
        savepoint.rollback()
        transaction.rollback()
