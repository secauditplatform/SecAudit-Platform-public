"""Use playbook version 1.0 instead of the legacy 1.0.0 default.

Revision ID: 043_playbook_version_1_0
Revises: 042_credential_is_ephemeral
Create Date: 2026-08-18
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "043_playbook_version_1_0"
down_revision: Union[str, None] = "042_credential_is_ephemeral"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        "playbooks",
        "version",
        existing_type=sa.String(length=32),
        server_default="1.0",
        existing_nullable=False,
    )
    op.execute(sa.text("UPDATE playbooks SET version = '1.0'"))


def downgrade() -> None:
    op.execute(sa.text("UPDATE playbooks SET version = '1.0.0' WHERE version = '1.0'"))
    op.alter_column(
        "playbooks",
        "version",
        existing_type=sa.String(length=32),
        server_default="1.0.0",
        existing_nullable=False,
    )
