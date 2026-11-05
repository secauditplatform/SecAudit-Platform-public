"""Add immutable profile versions selecting which requirements a run evaluates.

Revision ID: 074_profile_versions
Revises: 073_user_token_version
Create Date: 2026-11-02
"""

import sqlalchemy as sa
from alembic import op

revision = "074_profile_versions"
down_revision = "073_user_token_version"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "profile_versions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "profile_id",
            sa.Integer(),
            sa.ForeignKey("profiles.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("number", sa.Integer(), nullable=False),
        sa.Column("label", sa.String(length=128), nullable=True),
        sa.Column("requirement_ids", sa.JSON(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_by", sa.String(length=128), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("profile_id", "number", name="uq_profile_version_number"),
    )
    op.create_index("ix_profile_versions_profile_id", "profile_versions", ["profile_id"])
    op.create_index(
        "uq_profile_version_active",
        "profile_versions",
        ["profile_id"],
        unique=True,
        postgresql_where=sa.text("is_active"),
    )
    op.add_column("jobs", sa.Column("profile_version_id", sa.Integer(), nullable=True))
    op.create_foreign_key(
        "jobs_profile_version_id_fkey",
        "jobs",
        "profile_versions",
        ["profile_version_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_jobs_profile_version_id", "jobs", ["profile_version_id"])


def downgrade() -> None:
    op.drop_index("ix_jobs_profile_version_id", table_name="jobs")
    op.drop_constraint("jobs_profile_version_id_fkey", "jobs", type_="foreignkey")
    op.drop_column("jobs", "profile_version_id")
    op.drop_index("uq_profile_version_active", table_name="profile_versions")
    op.drop_index("ix_profile_versions_profile_id", table_name="profile_versions")
    op.drop_table("profile_versions")
