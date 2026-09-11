"""Add OS metadata columns to profiles.

Revision ID: 030_profile_os_metadata
Revises: 029_rename_standards_to_profiles
Create Date: 2026-07-20
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "030_profile_os_metadata"
down_revision: Union[str, None] = "029_rename_standards_to_profiles"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("profiles", sa.Column("os_name", sa.String(length=128), nullable=True))
    op.add_column("profiles", sa.Column("os_version", sa.String(length=64), nullable=True))
    op.add_column("profiles", sa.Column("os_vendor", sa.String(length=128), nullable=True))
    op.create_index("ix_profiles_os_name", "profiles", ["os_name"])


def downgrade() -> None:
    op.drop_index("ix_profiles_os_name", table_name="profiles")
    op.drop_column("profiles", "os_vendor")
    op.drop_column("profiles", "os_version")
    op.drop_column("profiles", "os_name")
