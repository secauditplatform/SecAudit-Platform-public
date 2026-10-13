"""Per-view Audit Map layout positions.

Revision ID: 063_audit_map_layout_view
Revises: 062_audit_map
Create Date: 2026-10-09
"""

import sqlalchemy as sa
from alembic import op

revision = "063_audit_map_layout_view"
down_revision = "062_audit_map"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "audit_map_layouts",
        sa.Column("view", sa.String(length=32), nullable=False, server_default="network"),
    )
    op.drop_constraint("uq_audit_map_layout_owner_host", "audit_map_layouts", type_="unique")
    op.create_unique_constraint(
        "uq_audit_map_layout_owner_host_view",
        "audit_map_layouts",
        ["owner_sub", "host_id", "view"],
    )


def downgrade() -> None:
    op.drop_constraint("uq_audit_map_layout_owner_host_view", "audit_map_layouts", type_="unique")
    op.create_unique_constraint(
        "uq_audit_map_layout_owner_host",
        "audit_map_layouts",
        ["owner_sub", "host_id"],
    )
    op.drop_column("audit_map_layouts", "view")
