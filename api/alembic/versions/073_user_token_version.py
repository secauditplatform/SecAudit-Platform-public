"""Add a per-user token version for password-change session revocation.

Revision ID: 073_user_token_version
Revises: 072_aag_timeout_minutes
Create Date: 2026-10-21
"""

import sqlalchemy as sa
from alembic import op

revision = "073_user_token_version"
down_revision = "072_aag_timeout_minutes"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column("token_version", sa.Integer(), nullable=False, server_default=sa.text("0")),
    )


def downgrade() -> None:
    op.drop_column("users", "token_version")
