"""Run a check as the login user, without sudo.

Revision ID: 092_skip_become
Revises: 091_profile_fit_directory_map
Create Date: 2026-11-23
"""

import sqlalchemy as sa

from alembic import op

revision = "092_skip_become"
down_revision = "091_profile_fit_directory_map"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "credentials",
        sa.Column("skip_become", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(
        "audit_flow_credentials",
        sa.Column("skip_become", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("audit_flow_credentials", "skip_become")
    op.drop_column("credentials", "skip_become")
