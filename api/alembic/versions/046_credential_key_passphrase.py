"""Optional encrypted passphrase for SSH private keys.

Revision ID: 046_credential_key_passphrase
Revises: 045_host_credentials
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "046_credential_key_passphrase"
down_revision: Union[str, None] = "045_host_credentials"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("credentials", sa.Column("encrypted_key_passphrase", sa.Text(), nullable=True))
    op.add_column(
        "audit_flow_credentials",
        sa.Column("encrypted_key_passphrase", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("audit_flow_credentials", "encrypted_key_passphrase")
    op.drop_column("credentials", "encrypted_key_passphrase")
