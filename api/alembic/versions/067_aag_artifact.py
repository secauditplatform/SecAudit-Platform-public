"""AAG task artifacts, stored apart from check results.

Revision ID: 067_aag_artifact
Revises: 066_aag_connection
Create Date: 2026-10-13
"""

import sqlalchemy as sa
from alembic import op

revision = "067_aag_artifact"
down_revision = "066_aag_connection"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "aag_artifacts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False, server_default="pending"),
        sa.Column("requested_by", sa.String(length=256), nullable=True),
        sa.Column("provider", sa.String(length=16), nullable=False),
        sa.Column("model_name", sa.String(length=256), nullable=True),
        sa.Column("target_host", sa.String(length=512), nullable=True),
        sa.Column("input_hash", sa.String(length=64), nullable=False),
        sa.Column("prompt_redacted", sa.Text(), nullable=False),
        sa.Column("response_text", sa.Text(), nullable=True),
        sa.Column("citations_json", sa.JSON(), nullable=True),
        sa.Column("run_id", sa.Integer(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_aag_artifacts_kind", "aag_artifacts", ["kind"])
    op.create_index("ix_aag_artifacts_run_id", "aag_artifacts", ["run_id"])
    op.create_index("ix_aag_artifacts_created_at", "aag_artifacts", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_aag_artifacts_created_at", table_name="aag_artifacts")
    op.drop_index("ix_aag_artifacts_run_id", table_name="aag_artifacts")
    op.drop_index("ix_aag_artifacts_kind", table_name="aag_artifacts")
    op.drop_table("aag_artifacts")
