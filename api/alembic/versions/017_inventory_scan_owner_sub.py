"""inventory scan owner_sub for auto-created hosts

Revision ID: 017_inventory_scan_owner_sub
Revises: 016_credential_owner_sub
Create Date: 2026-07-12
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "017_inventory_scan_owner_sub"
down_revision: Union[str, None] = "016_credential_owner_sub"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("inventory_scans", sa.Column("owner_sub", sa.String(length=256), nullable=True))
    op.create_index("ix_inventory_scans_owner_sub", "inventory_scans", ["owner_sub"])


def downgrade() -> None:
    op.drop_index("ix_inventory_scans_owner_sub", table_name="inventory_scans")
    op.drop_column("inventory_scans", "owner_sub")
