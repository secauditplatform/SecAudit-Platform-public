"""Add change_ticket to compliance waivers.

Revision ID: 052_waiver_change_ticket
Revises: 051_audit_flow_templates
Create Date: 2026-09-16
"""

from alembic import op
import sqlalchemy as sa

revision = "052_waiver_change_ticket"
down_revision = "051_audit_flow_templates"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "compliance_waivers",
        sa.Column("change_ticket", sa.String(length=128), nullable=True),
    )
    op.create_index(
        "ix_compliance_waivers_change_ticket",
        "compliance_waivers",
        ["change_ticket"],
    )


def downgrade() -> None:
    op.drop_index("ix_compliance_waivers_change_ticket", table_name="compliance_waivers")
    op.drop_column("compliance_waivers", "change_ticket")
