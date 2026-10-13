"""Customer CVE feed references shown next to FAIL.

Revision ID: 065_cve_feed
Revises: 064_audit_flow_inventory_scope
Create Date: 2026-10-12
"""

import sqlalchemy as sa
from alembic import op

revision = "065_cve_feed"
down_revision = "064_audit_flow_inventory_scope"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "cve_feed_entries",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("requirement_id", sa.String(length=128), nullable=False, server_default=""),
        sa.Column("profile_name", sa.String(length=256), nullable=False, server_default=""),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column(
            "imported_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "requirement_id <> '' OR profile_name <> ''",
            name="ck_cve_feed_entry_target",
        ),
        sa.UniqueConstraint(
            "cve_id",
            "requirement_id",
            "profile_name",
            name="uq_cve_feed_entry",
        ),
    )
    op.create_index("ix_cve_feed_entries_cve_id", "cve_feed_entries", ["cve_id"])
    op.create_index("ix_cve_feed_entries_requirement_id", "cve_feed_entries", ["requirement_id"])
    op.create_index("ix_cve_feed_entries_profile_name", "cve_feed_entries", ["profile_name"])


def downgrade() -> None:
    op.drop_index("ix_cve_feed_entries_profile_name", table_name="cve_feed_entries")
    op.drop_index("ix_cve_feed_entries_requirement_id", table_name="cve_feed_entries")
    op.drop_index("ix_cve_feed_entries_cve_id", table_name="cve_feed_entries")
    op.drop_table("cve_feed_entries")
