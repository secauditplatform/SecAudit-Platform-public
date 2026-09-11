"""Add SIEM notification channel type for audit log export.

Revision ID: 020_siem_channel_type
Revises: 019_fix_outboxstatus_enum_case
Create Date: 2026-07-12
"""

from typing import Sequence, Union

from alembic import op

revision: str = "020_siem_channel_type"
down_revision: Union[str, None] = "019_fix_outboxstatus_enum_case"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE notificationchanneltype ADD VALUE IF NOT EXISTS 'siem'")


def downgrade() -> None:
    # PostgreSQL cannot remove enum values safely; no-op downgrade.
    pass
