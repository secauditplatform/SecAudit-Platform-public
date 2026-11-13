"""Persist remediation workflow links (source audit run, re-audit run).

Revision ID: 081_remediation_workflow_links
Revises: 080_audit_flow_auto_execute
Create Date: 2026-11-10
"""

import sqlalchemy as sa
from alembic import op

revision = "081_remediation_workflow_links"
down_revision = "080_audit_flow_auto_execute"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "remediation_jobs",
        sa.Column("source_run_id", sa.Integer(), sa.ForeignKey("job_runs.id", ondelete="SET NULL"), nullable=True),
    )
    op.create_index("ix_remediation_jobs_source_run_id", "remediation_jobs", ["source_run_id"])
    op.add_column(
        "remediation_jobs",
        sa.Column(
            "workflow_reaudit_run_id",
            sa.Integer(),
            sa.ForeignKey("job_runs.id", ondelete="SET NULL"),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("remediation_jobs", "workflow_reaudit_run_id")
    op.drop_index("ix_remediation_jobs_source_run_id", table_name="remediation_jobs")
    op.drop_column("remediation_jobs", "source_run_id")
