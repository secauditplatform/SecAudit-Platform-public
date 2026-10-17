"""Screen metadata for AAG artifacts.

Revision ID: 068_aag_screen_meta
Revises: 067_aag_artifact
Create Date: 2026-10-13
"""

import sqlalchemy as sa
from alembic import op

revision = "068_aag_screen_meta"
down_revision = "067_aag_artifact"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("aag_artifacts", sa.Column("meta_json", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("aag_artifacts", "meta_json")
