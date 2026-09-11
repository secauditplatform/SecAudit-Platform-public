"""Durable dispatch claims, terminal runs, and idempotent results.

Revision ID: 027_dispatch_idempotency
Revises: 026_dynamic_target_owner_scope
Create Date: 2026-07-17
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "027_dispatch_idempotency"
down_revision: Union[str, None] = "026_dynamic_target_owner_scope"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _deduplicate(table: str, key_columns: tuple[str, ...]) -> None:
    partition = ", ".join(key_columns)
    op.execute(
        sa.text(
            f"""
            DELETE FROM {table}
            WHERE id IN (
                SELECT id
                FROM (
                    SELECT id, row_number() OVER (
                        PARTITION BY {partition} ORDER BY id DESC
                    ) AS duplicate_number
                    FROM {table}
                ) duplicates
                WHERE duplicate_number > 1
            )
            """
        )
    )


def upgrade() -> None:
    # Enum additions are intentionally additive so all existing outbox rows and
    # their exact statuses remain intact.
    op.execute(sa.text("ALTER TYPE outboxstatus ADD VALUE IF NOT EXISTS 'DISPATCHING'"))
    op.execute(sa.text("ALTER TYPE outboxstatus ADD VALUE IF NOT EXISTS 'CANCELLED'"))

    op.add_column(
        "task_outbox",
        sa.Column("dispatch_started_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.execute(
        sa.text(
            """
            WITH duplicates AS (
                SELECT id, row_number() OVER (
                    PARTITION BY celery_task_id ORDER BY id
                ) AS duplicate_number
                FROM task_outbox
                WHERE celery_task_id IS NOT NULL
            )
            UPDATE task_outbox
            SET celery_task_id = NULL
            WHERE id IN (
                SELECT id FROM duplicates WHERE duplicate_number > 1
            )
            """
        )
    )
    op.execute(
        sa.text(
            """
            UPDATE task_outbox
            SET celery_task_id = 'secaudit-outbox-' || id::text
            WHERE celery_task_id IS NULL
            """
        )
    )
    op.create_unique_constraint(
        "uq_task_outbox_celery_task_id", "task_outbox", ["celery_task_id"]
    )
    op.create_index(
        "ix_task_outbox_dispatch_lease",
        "task_outbox",
        ["status", "dispatch_started_at"],
    )

    _deduplicate("check_results", ("job_run_id", "host_id", "rule_tech_name"))
    _deduplicate(
        "remediation_results",
        ("remediation_run_id", "host_id", "script_name"),
    )
    _deduplicate("inventory_scan_results", ("scan_id", "ip_address"))
    op.create_unique_constraint(
        "uq_check_result_run_host_rule",
        "check_results",
        ["job_run_id", "host_id", "rule_tech_name"],
    )
    op.create_unique_constraint(
        "uq_remediation_result_run_host_script",
        "remediation_results",
        ["remediation_run_id", "host_id", "script_name"],
    )
    op.create_unique_constraint(
        "uq_inventory_scan_result",
        "inventory_scan_results",
        ["scan_id", "ip_address"],
    )

    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION prevent_terminal_run_transition()
            RETURNS trigger AS $$
            BEGIN
                IF OLD.status IN ('COMPLETED', 'FAILED', 'CANCELLED')
                   AND NEW.status IS DISTINCT FROM OLD.status THEN
                    RAISE EXCEPTION 'terminal run status % cannot transition to %',
                        OLD.status, NEW.status;
                END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql
            """
        )
    )
    for table in ("job_runs", "remediation_runs", "inventory_scans"):
        op.execute(
            sa.text(
                f"""
                CREATE TRIGGER trg_{table}_terminal_status
                BEFORE UPDATE OF status ON {table}
                FOR EACH ROW EXECUTE FUNCTION prevent_terminal_run_transition()
                """
            )
        )


def downgrade() -> None:
    for table in ("inventory_scans", "remediation_runs", "job_runs"):
        op.execute(sa.text(f"DROP TRIGGER IF EXISTS trg_{table}_terminal_status ON {table}"))
    op.execute(sa.text("DROP FUNCTION IF EXISTS prevent_terminal_run_transition()"))
    op.drop_constraint(
        "uq_inventory_scan_result", "inventory_scan_results", type_="unique"
    )
    op.drop_constraint(
        "uq_remediation_result_run_host_script",
        "remediation_results",
        type_="unique",
    )
    op.drop_constraint(
        "uq_check_result_run_host_rule", "check_results", type_="unique"
    )
    op.drop_index("ix_task_outbox_dispatch_lease", table_name="task_outbox")
    op.drop_constraint(
        "uq_task_outbox_celery_task_id", "task_outbox", type_="unique"
    )
    op.drop_column("task_outbox", "dispatch_started_at")
    # PostgreSQL cannot safely remove enum values in-place. The additive labels
    # remain unused after downgrade.
