"""host_group_members association table

Revision ID: 002_host_group_members
Revises: 001_initial
Create Date: 2026-07-07

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "002_host_group_members"
down_revision: Union[str, None] = "001_initial"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "host_group_members",
        sa.Column("host_group_id", sa.Integer(), nullable=False),
        sa.Column("host_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["host_group_id"], ["host_groups.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("host_group_id", "host_id"),
    )


def downgrade() -> None:
    op.drop_table("host_group_members")
