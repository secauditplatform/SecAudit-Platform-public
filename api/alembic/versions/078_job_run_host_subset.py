"""Store per-run host subset for partial restarts.

Revision ID: 078_job_run_host_subset
Revises: 077_active_remediation_script
Create Date: 2026-11-07
"""

import sqlalchemy as sa
from alembic import op

revision = "078_job_run_host_subset"
down_revision = "077_active_remediation_script"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("job_runs", sa.Column("host_ids", sa.JSON(), nullable=True))
    op.add_column(
        "job_runs",
        sa.Column("is_partial", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("job_runs", sa.Column("subset_kind", sa.String(16), nullable=True))
    op.add_column(
        "job_runs",
        sa.Column(
            "source_run_id",
            sa.Integer(),
            sa.ForeignKey("job_runs.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )
    op.create_index("ix_job_runs_source_run_id", "job_runs", ["source_run_id"])


def downgrade() -> None:
    op.drop_index("ix_job_runs_source_run_id", table_name="job_runs")
    op.drop_column("job_runs", "source_run_id")
    op.drop_column("job_runs", "subset_kind")
    op.drop_column("job_runs", "is_partial")
    op.drop_column("job_runs", "host_ids")
