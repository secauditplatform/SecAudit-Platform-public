"""Keep exactly one active audit script per profile and default it to the packaged one.

Revision ID: 076_check_script_single_primary
Revises: 075_check_script_primary
Create Date: 2026-11-03
"""

import sqlalchemy as sa
from alembic import op

revision = "076_check_script_single_primary"
down_revision = "075_check_script_primary"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_index("uq_check_script_primary", table_name="check_scripts")
    # The first imported script is the one that ships with the profile; uploads get higher ids.
    op.execute("UPDATE check_scripts SET is_primary = false WHERE is_primary")
    op.execute(
        """
        UPDATE check_scripts SET is_primary = true
        WHERE id IN (
            SELECT MIN(id) FROM check_scripts
            WHERE script_kind = 'AUDIT'
            GROUP BY profile_id
        )
        """
    )
    op.create_index(
        "uq_check_script_primary",
        "check_scripts",
        ["profile_id"],
        unique=True,
        postgresql_where=sa.text("is_primary AND script_kind = 'AUDIT'"),
    )


def downgrade() -> None:
    op.drop_index("uq_check_script_primary", table_name="check_scripts")
    op.create_index(
        "uq_check_script_primary",
        "check_scripts",
        ["profile_id", "execution_type"],
        unique=True,
        postgresql_where=sa.text("is_primary AND script_kind = 'AUDIT'"),
    )
