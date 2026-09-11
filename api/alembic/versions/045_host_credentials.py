"""Host-to-credential links for multiple SSH auth methods per host.

Revision ID: 045_host_credentials
Revises: 044_compliance_playbook_dedupe
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "045_host_credentials"
down_revision: Union[str, None] = "044_compliance_playbook_dedupe"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "host_credentials",
        sa.Column("host_id", sa.Integer(), sa.ForeignKey("hosts.id", ondelete="CASCADE"), primary_key=True),
        sa.Column(
            "credential_id",
            sa.Integer(),
            sa.ForeignKey("credentials.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("sort_order", sa.Integer(), nullable=False, server_default="0"),
    )
    op.create_index("ix_host_credentials_host_id", "host_credentials", ["host_id"])
    op.execute(
        """
        INSERT INTO host_credentials (host_id, credential_id, sort_order)
        SELECT id, credential_id, 0
        FROM hosts
        WHERE credential_id IS NOT NULL
        """
    )


def downgrade() -> None:
    op.drop_index("ix_host_credentials_host_id", table_name="host_credentials")
    op.drop_table("host_credentials")
