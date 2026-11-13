"""Widen rule tech_name columns to 256 characters.

Revision ID: 079_rule_tech_name_256
Revises: 078_job_run_host_subset
Create Date: 2026-11-09
"""

import sqlalchemy as sa
from alembic import op

revision = "079_rule_tech_name_256"
down_revision = "078_job_run_host_subset"
branch_labels = None
depends_on = None

_COLUMNS = (
    ("rules", "tech_name"),
    ("interpreter_rules", "tech_name"),
    ("check_results", "rule_tech_name"),
    ("compliance_waivers", "rule_tech_name"),
)


def upgrade() -> None:
    for table, column in _COLUMNS:
        op.alter_column(
            table,
            column,
            existing_type=sa.String(length=64),
            type_=sa.String(length=256),
            existing_nullable=False,
        )


def downgrade() -> None:
    for table, column in _COLUMNS:
        op.alter_column(
            table,
            column,
            existing_type=sa.String(length=256),
            type_=sa.String(length=64),
            existing_nullable=False,
        )
