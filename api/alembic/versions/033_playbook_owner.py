"""playbook owner_sub for object rbac

Revision ID: 033_playbook_owner
Revises: 032_task_dead_letters
Create Date: 2026-07-27
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "033_playbook_owner"
down_revision: Union[str, None] = "032_task_dead_letters"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {col["name"] for col in inspector.get_columns("playbooks")}
    if "owner_sub" not in columns:
        op.add_column(
            "playbooks",
            sa.Column("owner_sub", sa.String(length=256), nullable=True),
        )
    indexes = {idx["name"] for idx in inspector.get_indexes("playbooks")}
    if "ix_playbooks_owner_sub" not in indexes:
        op.create_index("ix_playbooks_owner_sub", "playbooks", ["owner_sub"])


def downgrade() -> None:
    op.drop_index("ix_playbooks_owner_sub", table_name="playbooks")
    op.drop_column("playbooks", "owner_sub")
