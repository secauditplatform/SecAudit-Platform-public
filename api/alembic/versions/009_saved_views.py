"""add saved_views table for user filter presets

Revision ID: 009_saved_views
Revises: 008_scap_xccdf
Create Date: 2026-07-08
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "009_saved_views"
down_revision: Union[str, None] = "008_scap_xccdf"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "saved_views",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("owner_sub", sa.String(length=256), nullable=False),
        sa.Column("owner_username", sa.String(length=128), nullable=False),
        sa.Column("page", sa.String(length=64), nullable=False),
        sa.Column("filters", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("owner_sub", "page", "name", name="uq_saved_views_owner_page_name"),
    )
    op.create_index("ix_saved_views_owner_sub", "saved_views", ["owner_sub"])
    op.create_index("ix_saved_views_page", "saved_views", ["page"])


def downgrade() -> None:
    op.drop_index("ix_saved_views_page", table_name="saved_views")
    op.drop_index("ix_saved_views_owner_sub", table_name="saved_views")
    op.drop_table("saved_views")
