"""dynamic inventory tables and targeting columns

Revision ID: 006_dynamic_inventory_tables
Revises: 005_drop_compliance_waivers
Create Date: 2026-07-07
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "006_dynamic_inventory_tables"
down_revision: Union[str, None] = "005_drop_compliance_waivers"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "host_groups",
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=True),
    )

    op.create_table(
        "host_tags",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "host_tag_links",
        sa.Column("host_id", sa.Integer(), nullable=False),
        sa.Column("tag_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tag_id"], ["host_tags.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("host_id", "tag_id"),
    )

    op.add_column("jobs", sa.Column("dynamic_filter", sa.JSON(), nullable=True))
    op.add_column("remediation_jobs", sa.Column("host_group_id", sa.Integer(), nullable=True))
    op.add_column("remediation_jobs", sa.Column("dynamic_filter", sa.JSON(), nullable=True))
    op.create_foreign_key(
        "fk_remediation_jobs_host_group_id",
        "remediation_jobs",
        "host_groups",
        ["host_group_id"],
        ["id"],
    )


def downgrade() -> None:
    op.drop_constraint("fk_remediation_jobs_host_group_id", "remediation_jobs", type_="foreignkey")
    op.drop_column("remediation_jobs", "dynamic_filter")
    op.drop_column("remediation_jobs", "host_group_id")
    op.drop_column("jobs", "dynamic_filter")
    op.drop_table("host_tag_links")
    op.drop_table("host_tags")
    op.drop_column("host_groups", "created_at")
