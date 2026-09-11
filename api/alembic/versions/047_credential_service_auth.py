"""Optional service credentials on host credentials (DB, middleware, etc.).

Revision ID: 047_credential_service_auth
Revises: 046_credential_key_passphrase
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "047_credential_service_auth"
down_revision: Union[str, None] = "046_credential_key_passphrase"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("credentials", sa.Column("service_username", sa.String(length=128), nullable=True))
    op.add_column("credentials", sa.Column("encrypted_service_secret", sa.Text(), nullable=True))
    op.add_column("audit_flow_credentials", sa.Column("service_username", sa.String(length=128), nullable=True))
    op.add_column("audit_flow_credentials", sa.Column("encrypted_service_secret", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("audit_flow_credentials", "encrypted_service_secret")
    op.drop_column("audit_flow_credentials", "service_username")
    op.drop_column("credentials", "encrypted_service_secret")
    op.drop_column("credentials", "service_username")
