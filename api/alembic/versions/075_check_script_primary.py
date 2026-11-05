"""Add the profile's primary audit script used when a job has no explicit choice.

Revision ID: 075_check_script_primary
Revises: 074_profile_versions
Create Date: 2026-11-03
"""

import sqlalchemy as sa
from alembic import op

revision = "075_check_script_primary"
down_revision = "074_profile_versions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "check_scripts",
        sa.Column("is_primary", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.create_index(
        "uq_check_script_primary",
        "check_scripts",
        ["profile_id", "execution_type"],
        unique=True,
        postgresql_where=sa.text("is_primary AND script_kind = 'AUDIT'"),
    )


def downgrade() -> None:
    op.drop_index("uq_check_script_primary", table_name="check_scripts")
    op.drop_column("check_scripts", "is_primary")
