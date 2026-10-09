"""Add Telegram notification channel type.

Revision ID: 058_telegram_channel_type
Revises: 057_playbook_check_mode
Create Date: 2026-10-07
"""

from alembic import op

revision = "058_telegram_channel_type"
down_revision = "057_playbook_check_mode"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE notificationchanneltype ADD VALUE IF NOT EXISTS 'telegram'")


def downgrade() -> None:
    # PostgreSQL cannot remove enum values safely.
    pass
