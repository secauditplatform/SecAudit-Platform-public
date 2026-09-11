"""AuditFlow option to save discovered hosts into inventory.

Revision ID: 041_audit_flow_save_inventory
Revises: 040_audit_flow_quality
Create Date: 2026-08-15
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "041_audit_flow_save_inventory"
down_revision: Union[str, None] = "040_audit_flow_quality"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "audit_flow_runs",
        sa.Column("save_to_inventory", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("audit_flow_runs", "save_to_inventory")
