"""Add playbook platform (linux/windows/network).

Revision ID: 037_playbook_platform
Revises: 036_normalize_profile_family
Create Date: 2026-08-08
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "037_playbook_platform"
down_revision: Union[str, None] = "036_normalize_profile_family"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "playbooks",
        sa.Column("platform", sa.String(length=16), nullable=False, server_default="linux"),
    )
    op.execute(
        sa.text(
            """
            UPDATE playbooks
            SET platform = 'network'
            WHERE scope = 'network'
            """
        )
    )
    op.execute(
        sa.text(
            """
            UPDATE playbooks
            SET platform = 'windows'
            WHERE scope IS DISTINCT FROM 'network'
              AND (
                lower(name) LIKE 'windows%'
                OR lower(name) LIKE '%win-%'
                OR lower(name) LIKE '%-windows%'
                OR lower(name) LIKE '%windows(%'
              )
            """
        )
    )
    op.create_index("ix_playbooks_platform", "playbooks", ["platform"])


def downgrade() -> None:
    op.drop_index("ix_playbooks_platform", table_name="playbooks")
    op.drop_column("playbooks", "platform")
