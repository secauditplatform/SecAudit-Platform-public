"""Host OS version and directory import matching options.

Revision ID: 091_profile_fit_directory_map
Revises: 090_check_results_created_at_idx
Create Date: 2026-11-22
"""

import sqlalchemy as sa

from alembic import op

revision = "091_profile_fit_directory_map"
down_revision = "090_check_results_created_at_idx"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("hosts", sa.Column("os_version", sa.String(length=64), nullable=True))
    op.add_column("directory_sources", sa.Column("import_limit", sa.Integer(), nullable=True))
    op.add_column("directory_sources", sa.Column("computer_filter", sa.String(length=512), nullable=True))
    op.add_column("directory_sources", sa.Column("ou_field_map", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("directory_sources", "ou_field_map")
    op.drop_column("directory_sources", "computer_filter")
    op.drop_column("directory_sources", "import_limit")
    op.drop_column("hosts", "os_version")
