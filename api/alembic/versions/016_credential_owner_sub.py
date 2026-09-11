"""credential owner_sub for object rbac

Revision ID: 016_credential_owner_sub
Revises: 015_object_rbac
Create Date: 2026-07-10
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "016_credential_owner_sub"
down_revision: Union[str, None] = "015_object_rbac"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("credentials", sa.Column("owner_sub", sa.String(length=256), nullable=True))
    op.create_index("ix_credentials_owner_sub", "credentials", ["owner_sub"])


def downgrade() -> None:
    op.drop_index("ix_credentials_owner_sub", table_name="credentials")
    op.drop_column("credentials", "owner_sub")
