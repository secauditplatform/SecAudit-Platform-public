"""AD/LDAP directory sources and computer-import runs.

Revision ID: 059_directory_sources
Revises: 058_telegram_channel_type
Create Date: 2026-10-07
"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "059_directory_sources"
down_revision = "058_telegram_channel_type"
branch_labels = None
depends_on = None

jobstatus = postgresql.ENUM(
    "PENDING",
    "RUNNING",
    "COMPLETED",
    "FAILED",
    "CANCELLED",
    name="jobstatus",
    create_type=False,
)


def upgrade() -> None:
    op.create_table(
        "directory_sources",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("server", sa.String(length=256), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False, server_default="389"),
        sa.Column("use_ssl", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("start_tls", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("verify_tls", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("base_dn", sa.String(length=512), nullable=False),
        sa.Column("bind_dn", sa.String(length=512), nullable=False),
        sa.Column("encrypted_bind_password", sa.Text(), nullable=False),
        sa.Column("enabled_only", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("map_ou_to_site", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("owner_sub", sa.String(length=256), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_directory_sources_owner_sub", "directory_sources", ["owner_sub"])
    op.create_table(
        "directory_syncs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("source_id", sa.Integer(), nullable=False),
        sa.Column("status", jobstatus, nullable=False, server_default="PENDING"),
        sa.Column("hosts_found", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("hosts_created", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("hosts_updated", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("hosts_matched", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("owner_sub", sa.String(length=256), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["source_id"], ["directory_sources.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_directory_syncs_source_id", "directory_syncs", ["source_id"])
    op.create_index("ix_directory_syncs_owner_sub", "directory_syncs", ["owner_sub"])


def downgrade() -> None:
    op.drop_index("ix_directory_syncs_owner_sub", table_name="directory_syncs")
    op.drop_index("ix_directory_syncs_source_id", table_name="directory_syncs")
    op.drop_table("directory_syncs")
    op.drop_index("ix_directory_sources_owner_sub", table_name="directory_sources")
    op.drop_table("directory_sources")
