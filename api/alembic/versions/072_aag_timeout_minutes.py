"""Raise the AAG provider timeout to 120 minutes.

Revision ID: 072_aag_timeout_minutes
Revises: 071_aag_provider_selected
Create Date: 2026-10-14
"""

import sqlalchemy as sa
from alembic import op

revision = "072_aag_timeout_minutes"
down_revision = "071_aag_provider_selected"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "aag_provider_config",
        "timeout_seconds",
        server_default="7200",
        existing_type=sa.Integer(),
        existing_nullable=False,
    )
    op.execute("UPDATE aag_provider_config SET timeout_seconds = 7200")


def downgrade() -> None:
    op.alter_column(
        "aag_provider_config",
        "timeout_seconds",
        server_default="30",
        existing_type=sa.Integer(),
        existing_nullable=False,
    )
