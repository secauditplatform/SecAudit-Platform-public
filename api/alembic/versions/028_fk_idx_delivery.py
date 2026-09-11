"""Add FK lookup indexes and scheduled report delivery idempotency.

Revision ID: 028_fk_idx_delivery
Revises: 027_dispatch_idempotency
Create Date: 2026-07-18
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "028_fk_idx_delivery"
down_revision: Union[str, None] = "027_dispatch_idempotency"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_index("ix_job_runs_job_id", "job_runs", ["job_id"])
    op.create_index("ix_job_runs_job_id_created_at", "job_runs", ["job_id", "created_at"])
    op.create_index("ix_check_results_job_run_id", "check_results", ["job_run_id"])
    op.create_index("ix_check_results_host_id", "check_results", ["host_id"])
    op.create_index(
        "ix_remediation_runs_remediation_job_id",
        "remediation_runs",
        ["remediation_job_id"],
    )
    op.create_index(
        "ix_remediation_results_remediation_run_id",
        "remediation_results",
        ["remediation_run_id"],
    )
    op.create_index("ix_remediation_results_host_id", "remediation_results", ["host_id"])

    op.create_table(
        "scheduled_report_delivery_attempts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "schedule_id",
            sa.Integer(),
            sa.ForeignKey("scheduled_reports.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("delivery_key", sa.String(length=256), nullable=False),
        sa.Column(
            "job_run_id",
            sa.Integer(),
            sa.ForeignKey("job_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(length=32), nullable=False, server_default="claimed"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint(
            "schedule_id",
            "delivery_key",
            name="uq_scheduled_report_delivery_key",
        ),
    )
    op.create_index(
        "ix_scheduled_report_delivery_attempts_schedule_id",
        "scheduled_report_delivery_attempts",
        ["schedule_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_scheduled_report_delivery_attempts_schedule_id",
        table_name="scheduled_report_delivery_attempts",
    )
    op.drop_table("scheduled_report_delivery_attempts")
    op.drop_index("ix_remediation_results_host_id", table_name="remediation_results")
    op.drop_index(
        "ix_remediation_results_remediation_run_id", table_name="remediation_results"
    )
    op.drop_index(
        "ix_remediation_runs_remediation_job_id", table_name="remediation_runs"
    )
    op.drop_index("ix_check_results_host_id", table_name="check_results")
    op.drop_index("ix_check_results_job_run_id", table_name="check_results")
    op.drop_index("ix_job_runs_job_id_created_at", table_name="job_runs")
    op.drop_index("ix_job_runs_job_id", table_name="job_runs")
