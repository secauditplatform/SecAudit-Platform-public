"""Remediation check-mode statuses and per-rule results.

Revision ID: 084_remediation_rule_results
Revises: 083_credential_become
Create Date: 2026-11-14
"""

import sqlalchemy as sa
from alembic import op

revision = "084_remediation_rule_results"
down_revision = "083_credential_become"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE checkstatus ADD VALUE IF NOT EXISTS 'CHANGED'")
    op.execute("ALTER TYPE checkstatus ADD VALUE IF NOT EXISTS 'UNCHANGED'")

    op.add_column(
        "remediation_results",
        sa.Column(
            "rule_tech_name",
            sa.String(length=256),
            nullable=False,
            server_default="",
        ),
    )
    op.drop_constraint(
        "uq_remediation_result_run_host_script",
        "remediation_results",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_remediation_result_run_host_script_rule",
        "remediation_results",
        ["remediation_run_id", "host_id", "script_name", "rule_tech_name"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_remediation_result_run_host_script_rule",
        "remediation_results",
        type_="unique",
    )
    op.drop_column("remediation_results", "rule_tech_name")
    op.create_unique_constraint(
        "uq_remediation_result_run_host_script",
        "remediation_results",
        ["remediation_run_id", "host_id", "script_name"],
    )
    # PostgreSQL cannot remove enum values safely; leave CHANGED/UNCHANGED.
