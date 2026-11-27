"""Profile variable schema and frozen version values.

Revision ID: 094_profile_variables
Revises: 093_waiver_scope_rbac
Create Date: 2026-11-25
"""

import sqlalchemy as sa

from alembic import op

revision = "094_profile_variables"
down_revision = "093_waiver_scope_rbac"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "profiles",
        sa.Column("variable_schema", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )
    op.add_column("profile_versions", sa.Column("variable_values", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("profile_versions", "variable_values")
    op.drop_column("profiles", "variable_schema")
