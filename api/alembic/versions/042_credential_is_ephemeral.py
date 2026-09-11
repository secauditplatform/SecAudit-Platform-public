"""Mark AuditFlow job credentials as ephemeral so they stay out of the catalog.

Revision ID: 042_credential_is_ephemeral
Revises: 041_audit_flow_save_inventory
Create Date: 2026-08-18
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "042_credential_is_ephemeral"
down_revision: Union[str, None] = "041_audit_flow_save_inventory"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "credentials",
        sa.Column("is_ephemeral", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.execute(
        sa.text(
            "UPDATE credentials SET is_ephemeral = true "
            "WHERE description IN ('AuditFlow ephemeral', 'AuditFlow inventory')"
        )
    )


def downgrade() -> None:
    op.drop_column("credentials", "is_ephemeral")
