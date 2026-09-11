"""drop saved_views table (feature removed for usability)

Revision ID: 010_drop_saved_views
Revises: 009_saved_views
Create Date: 2026-07-08
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "010_drop_saved_views"
down_revision: Union[str, None] = "009_saved_views"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_index("ix_saved_views_page", table_name="saved_views")
    op.drop_index("ix_saved_views_owner_sub", table_name="saved_views")
    op.drop_table("saved_views")


def downgrade() -> None:
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
