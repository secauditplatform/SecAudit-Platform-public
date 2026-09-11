"""notification channel owner_sub for object rbac

Revision ID: 031_notify_channel_owner
Revises: 030_profile_os_metadata
Create Date: 2026-07-27
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "031_notify_channel_owner"
down_revision: Union[str, None] = "030_profile_os_metadata"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "notification_channels",
        sa.Column("owner_sub", sa.String(length=256), nullable=True),
    )
    op.create_index(
        "ix_notification_channels_owner_sub",
        "notification_channels",
        ["owner_sub"],
    )


def downgrade() -> None:
    op.drop_index("ix_notification_channels_owner_sub", table_name="notification_channels")
    op.drop_column("notification_channels", "owner_sub")
