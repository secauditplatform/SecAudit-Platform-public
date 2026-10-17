"""Call log metrics without prompts or keys.

Revision ID: 070_aag_call_metrics
Revises: 069_aag_contour_enabled
Create Date: 2026-10-13
"""

import sqlalchemy as sa
from alembic import op

revision = "070_aag_call_metrics"
down_revision = "069_aag_contour_enabled"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("aag_call_log", sa.Column("kind", sa.String(length=16), nullable=True))
    op.add_column("aag_call_log", sa.Column("draft_type", sa.String(length=32), nullable=True))
    op.add_column(
        "aag_call_log",
        sa.Column("outcome", sa.String(length=16), nullable=False, server_default="ok"),
    )
    op.add_column("aag_call_log", sa.Column("error_code", sa.String(length=32), nullable=True))
    op.add_column("aag_call_log", sa.Column("duration_ms", sa.Integer(), nullable=True))
    op.add_column("aag_call_log", sa.Column("run_id", sa.Integer(), nullable=True))
    op.add_column(
        "aag_call_log",
        sa.Column("in_perimeter", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.add_column("aag_call_log", sa.Column("token_count", sa.Integer(), nullable=True))
    op.execute("UPDATE aag_call_log SET in_perimeter = true WHERE provider = 'internal'")


def downgrade() -> None:
    op.drop_column("aag_call_log", "token_count")
    op.drop_column("aag_call_log", "in_perimeter")
    op.drop_column("aag_call_log", "run_id")
    op.drop_column("aag_call_log", "duration_ms")
    op.drop_column("aag_call_log", "error_code")
    op.drop_column("aag_call_log", "outcome")
    op.drop_column("aag_call_log", "draft_type")
    op.drop_column("aag_call_log", "kind")
