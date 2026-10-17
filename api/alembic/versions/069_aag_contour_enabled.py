"""Admin switch for the AAG contour on the connection screen.

Revision ID: 069_aag_contour_enabled
Revises: 068_aag_screen_meta
Create Date: 2026-10-13
"""

import sqlalchemy as sa
from alembic import op

revision = "069_aag_contour_enabled"
down_revision = "068_aag_screen_meta"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "aag_provider_config",
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("aag_provider_config", "enabled")
