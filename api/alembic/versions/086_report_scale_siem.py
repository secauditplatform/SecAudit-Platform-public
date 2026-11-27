"""Job run counters and report artifacts.

Revision ID: 086_report_scale_siem
Revises: 085_asset_identity
Create Date: 2026-11-14
"""

import sqlalchemy as sa
from alembic import op

revision = "086_report_scale_siem"
down_revision = "085_asset_identity"
branch_labels = None
depends_on = None

_COUNTERS = ("pass_count", "fail_count", "skip_count", "error_count", "check_count")


def upgrade() -> None:
    for name in _COUNTERS:
        op.add_column("job_runs", sa.Column(name, sa.Integer(), nullable=True))

    op.create_table(
        "report_artifacts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("job_run_id", sa.Integer(), sa.ForeignKey("job_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("mode", sa.String(length=16), nullable=False),
        sa.Column("locale", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("file_path", sa.Text(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_report_artifacts_job_run_id", "report_artifacts", ["job_run_id"])

    # Runs with no check_results keep NULL counters (readers fall back to live counts).
    op.execute(
        sa.text(
            """
            UPDATE job_runs SET
                pass_count = agg.pass_count,
                fail_count = agg.fail_count,
                skip_count = agg.skip_count,
                error_count = agg.error_count,
                check_count = agg.check_count
            FROM (
                SELECT job_run_id,
                       count(*) FILTER (WHERE status::text IN ('pass', 'PASS')) AS pass_count,
                       count(*) FILTER (WHERE status::text IN ('fail', 'FAIL')) AS fail_count,
                       count(*) FILTER (WHERE status::text IN ('skip', 'SKIP')) AS skip_count,
                       count(*) FILTER (WHERE status::text IN ('error', 'ERROR')) AS error_count,
                       count(*) AS check_count
                FROM check_results
                GROUP BY job_run_id
            ) AS agg
            WHERE job_runs.id = agg.job_run_id
            """
        )
    )


def downgrade() -> None:
    op.drop_index("ix_report_artifacts_job_run_id", table_name="report_artifacts")
    op.drop_table("report_artifacts")
    for name in reversed(_COUNTERS):
        op.drop_column("job_runs", name)
