"""AuditFlow templates store an inventory tag/site rule.

Revision ID: 064_audit_flow_inventory_scope
Revises: 063_audit_map_layout_view
Create Date: 2026-10-11
"""

import sqlalchemy as sa
from alembic import op

revision = "064_audit_flow_inventory_scope"
down_revision = "063_audit_map_layout_view"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "audit_flow_templates",
        sa.Column("inventory_scope_json", sa.JSON(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("audit_flow_templates", "inventory_scope_json")
