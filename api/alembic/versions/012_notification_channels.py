"""notification channels for email/webhook/Slack/Teams alerts

Revision ID: 012_notification_channels
Revises: 011_drop_host_groups
Create Date: 2026-07-09
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "012_notification_channels"
down_revision: Union[str, None] = "011_drop_host_groups"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "notification_channels",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column(
            "channel_type",
            sa.Enum("email", "webhook", "slack", "teams", name="notificationchanneltype"),
            nullable=False,
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("events", sa.JSON(), nullable=False),
        sa.Column("config_json", sa.JSON(), nullable=True),
        sa.Column("encrypted_secret", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )


def downgrade() -> None:
    op.drop_table("notification_channels")
    op.execute("DROP TYPE IF EXISTS notificationchanneltype")
