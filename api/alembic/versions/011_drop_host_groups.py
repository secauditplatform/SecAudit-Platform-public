"""drop legacy host_groups tables and host_group_id columns

Revision ID: 011_drop_host_groups
Revises: 010_drop_saved_views
Create Date: 2026-07-09
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "011_drop_host_groups"
down_revision: Union[str, None] = "010_drop_saved_views"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint("jobs_host_group_id_fkey", "jobs", type_="foreignkey")
    op.drop_column("jobs", "host_group_id")

    op.drop_constraint("fk_remediation_jobs_host_group_id", "remediation_jobs", type_="foreignkey")
    op.drop_column("remediation_jobs", "host_group_id")

    op.drop_table("host_group_members")
    op.drop_table("host_groups")


def downgrade() -> None:
    op.create_table(
        "host_groups",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "host_group_members",
        sa.Column("host_group_id", sa.Integer(), nullable=False),
        sa.Column("host_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["host_group_id"], ["host_groups.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("host_group_id", "host_id"),
    )
    op.add_column("jobs", sa.Column("host_group_id", sa.Integer(), nullable=True))
    op.create_foreign_key("jobs_host_group_id_fkey", "jobs", "host_groups", ["host_group_id"], ["id"])
    op.add_column("remediation_jobs", sa.Column("host_group_id", sa.Integer(), nullable=True))
    op.create_foreign_key(
        "fk_remediation_jobs_host_group_id",
        "remediation_jobs",
        "host_groups",
        ["host_group_id"],
        ["id"],
    )
