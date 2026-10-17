"""AAG connection: single active provider config and secret-free call log.

Revision ID: 066_aag_connection
Revises: 065_cve_feed
Create Date: 2026-10-13
"""

import sqlalchemy as sa
from alembic import op

revision = "066_aag_connection"
down_revision = "065_cve_feed"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "aag_provider_config",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("provider", sa.String(length=16), nullable=False, server_default="none"),
        sa.Column("internal_base_url", sa.String(length=2048), nullable=True),
        sa.Column("external_base_url", sa.String(length=2048), nullable=True),
        sa.Column("model_name", sa.String(length=256), nullable=True),
        sa.Column("encrypted_external_key", sa.Text(), nullable=True),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False, server_default="30"),
        sa.Column("max_tokens", sa.Integer(), nullable=False, server_default="2000"),
        sa.Column("updated_by", sa.String(length=256), nullable=True),
        sa.Column("last_test_ok", sa.Boolean(), nullable=True),
        sa.Column("last_test_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_table(
        "aag_call_log",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("provider", sa.String(length=16), nullable=False),
        sa.Column("target_host", sa.String(length=512), nullable=True),
        sa.Column("model_name", sa.String(length=256), nullable=True),
        sa.Column("input_hash", sa.String(length=64), nullable=False),
        sa.Column("created_by", sa.String(length=256), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index("ix_aag_call_log_provider", "aag_call_log", ["provider"])
    op.create_index("ix_aag_call_log_created_at", "aag_call_log", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_aag_call_log_created_at", table_name="aag_call_log")
    op.drop_index("ix_aag_call_log_provider", table_name="aag_call_log")
    op.drop_table("aag_call_log")
    op.drop_table("aag_provider_config")
