"""Allow one active script per kind (audit and remediation) for a profile.

Revision ID: 077_active_remediation_script
Revises: 076_check_script_single_primary
Create Date: 2026-11-03
"""

import sqlalchemy as sa
from alembic import op

revision = "077_active_remediation_script"
down_revision = "076_check_script_single_primary"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_index("uq_check_script_primary", table_name="check_scripts")
    # The first remediation script imported with the profile becomes active.
    op.execute(
        """
        UPDATE check_scripts SET is_primary = true
        WHERE id IN (
            SELECT MIN(id) FROM check_scripts
            WHERE script_kind = 'REMEDIATION'
            GROUP BY profile_id
        )
        """
    )
    op.create_index(
        "uq_check_script_primary",
        "check_scripts",
        ["profile_id", "script_kind"],
        unique=True,
        postgresql_where=sa.text("is_primary"),
    )


def downgrade() -> None:
    op.drop_index("uq_check_script_primary", table_name="check_scripts")
    op.execute("UPDATE check_scripts SET is_primary = false WHERE script_kind = 'REMEDIATION'")
    op.create_index(
        "uq_check_script_primary",
        "check_scripts",
        ["profile_id"],
        unique=True,
        postgresql_where=sa.text("is_primary AND script_kind = 'AUDIT'"),
    )
