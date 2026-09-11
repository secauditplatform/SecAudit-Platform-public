"""Per-job webhook URLs for run notifications.

Revision ID: 022_job_webhooks
Revises: 021_host_ssh_fingerprint
Create Date: 2026-07-13
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "022_job_webhooks"
down_revision: Union[str, None] = "021_host_ssh_fingerprint"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _add_webhook_columns(table_name: str) -> None:
    op.add_column(
        table_name,
        sa.Column("webhook_enabled", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column(table_name, sa.Column("encrypted_webhook_url", sa.Text(), nullable=True))
    op.add_column(table_name, sa.Column("webhook_events", sa.JSON(), nullable=True))


def _drop_webhook_columns(table_name: str) -> None:
    op.drop_column(table_name, "webhook_events")
    op.drop_column(table_name, "encrypted_webhook_url")
    op.drop_column(table_name, "webhook_enabled")


def upgrade() -> None:
    _add_webhook_columns("jobs")
    _add_webhook_columns("remediation_jobs")


def downgrade() -> None:
    _drop_webhook_columns("remediation_jobs")
    _drop_webhook_columns("jobs")
