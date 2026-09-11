"""scheduled reports for cron email/S3 delivery

Revision ID: 013_scheduled_reports
Revises: 012_notification_channels
Create Date: 2026-07-09
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "013_scheduled_reports"
down_revision: Union[str, None] = "012_notification_channels"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scheduled_reports",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("job_id", sa.Integer(), nullable=False),
        sa.Column("cron_expression", sa.String(length=128), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column(
            "report_format",
            sa.Enum("html", "pdf", "both", name="scheduledreportformat"),
            nullable=False,
            server_default="pdf",
        ),
        sa.Column(
            "delivery_type",
            sa.Enum("email", "s3", name="scheduledreportdelivery"),
            nullable=False,
        ),
        sa.Column("config_json", sa.JSON(), nullable=True),
        sa.Column("encrypted_secret", sa.Text(), nullable=True),
        sa.Column("last_delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_delivered_run_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["last_delivered_run_id"], ["job_runs.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )


def downgrade() -> None:
    op.drop_table("scheduled_reports")
    op.execute("DROP TYPE IF EXISTS scheduledreportformat")
    op.execute("DROP TYPE IF EXISTS scheduledreportdelivery")
