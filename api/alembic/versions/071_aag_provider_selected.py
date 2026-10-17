"""Mark one saved AAG provider as the working provider.

Revision ID: 071_aag_provider_selected
Revises: 070_aag_call_metrics
Create Date: 2026-10-13
"""

import sqlalchemy as sa
from alembic import op

revision = "071_aag_provider_selected"
down_revision = "070_aag_call_metrics"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "aag_provider_config",
        sa.Column("selected", sa.Boolean(), nullable=False, server_default="false"),
    )
    op.execute(
        """
        UPDATE aag_provider_config
        SET selected = true
        WHERE id = (
            SELECT id FROM aag_provider_config
            ORDER BY enabled DESC, id ASC
            LIMIT 1
        )
        """
    )


def downgrade() -> None:
    op.drop_column("aag_provider_config", "selected")
