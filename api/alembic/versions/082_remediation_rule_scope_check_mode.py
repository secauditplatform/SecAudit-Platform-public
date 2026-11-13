"""Rule-scoped remediation, dry-run, and auto-recheck flags.

Revision ID: 082_remediation_rule_scope
Revises: 081_remediation_workflow_links
Create Date: 2026-11-11
"""

import sqlalchemy as sa
from alembic import op

revision = "082_remediation_rule_scope"
down_revision = "081_remediation_workflow_links"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("remediation_jobs", sa.Column("rule_tech_names", sa.JSON(), nullable=True))
    op.add_column(
        "remediation_jobs",
        sa.Column("check_mode", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.add_column(
        "remediation_jobs",
        sa.Column(
            "auto_recheck_failed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    op.drop_column("remediation_jobs", "auto_recheck_failed")
    op.drop_column("remediation_jobs", "check_mode")
    op.drop_column("remediation_jobs", "rule_tech_names")
