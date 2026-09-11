"""drop compliance waivers

Revision ID: 005_drop_compliance_waivers
Revises: 004_compliance_waivers
Create Date: 2026-07-07

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "005_drop_compliance_waivers"
down_revision: Union[str, None] = "004_compliance_waivers"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_index("ix_compliance_waivers_active", table_name="compliance_waivers")
    op.drop_index("ix_compliance_waivers_host_id", table_name="compliance_waivers")
    op.drop_index("ix_compliance_waivers_standard_id", table_name="compliance_waivers")
    op.drop_table("compliance_waivers")


def downgrade() -> None:
    op.create_table(
        "compliance_waivers",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("standard_id", sa.Integer(), nullable=False),
        sa.Column("rule_tech_name", sa.String(length=64), nullable=False),
        sa.Column("host_id", sa.Integer(), nullable=True),
        sa.Column("job_id", sa.Integer(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("approved_by", sa.String(length=128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"]),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"]),
        sa.ForeignKeyConstraint(["standard_id"], ["standards.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_compliance_waivers_standard_id", "compliance_waivers", ["standard_id"])
    op.create_index("ix_compliance_waivers_host_id", "compliance_waivers", ["host_id"])
    op.create_index("ix_compliance_waivers_active", "compliance_waivers", ["is_active"])
