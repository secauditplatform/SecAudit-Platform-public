"""Add SSH host key fingerprint columns for per-host pinning.

Revision ID: 021_host_ssh_fingerprint
Revises: 020_siem_channel_type
Create Date: 2026-07-12
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "021_host_ssh_fingerprint"
down_revision: Union[str, None] = "020_siem_channel_type"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("hosts", sa.Column("ssh_host_key_fingerprint", sa.String(length=128), nullable=True))
    op.add_column("hosts", sa.Column("ssh_known_hosts_entry", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("hosts", "ssh_known_hosts_entry")
    op.drop_column("hosts", "ssh_host_key_fingerprint")
