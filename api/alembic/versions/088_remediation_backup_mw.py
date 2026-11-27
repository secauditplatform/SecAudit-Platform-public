"""Remediation backup artifacts and maintenance windows.

Revision ID: 088_remediation_backup_mw
Revises: 087_vendor_dir_schedule
Create Date: 2026-11-14
"""

import sqlalchemy as sa
from alembic import op

revision = "088_remediation_backup_mw"
down_revision = "087_vendor_dir_schedule"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("remediation_runs", sa.Column("change_ticket", sa.String(length=128), nullable=True))
    op.add_column(
        "remediation_runs",
        sa.Column("backup_status", sa.String(length=16), nullable=False, server_default="none"),
    )
    op.add_column("remediation_runs", sa.Column("rollback_results_json", sa.JSON(), nullable=True))
    op.create_index("ix_remediation_runs_change_ticket", "remediation_runs", ["change_ticket"])

    op.create_table(
        "remediation_backup_artifacts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("remediation_run_id", sa.Integer(), sa.ForeignKey("remediation_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("host_id", sa.Integer(), sa.ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("platform", sa.String(length=16), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("path_or_key", sa.String(length=1024), nullable=False),
        sa.Column("encrypted_blob", sa.Text(), nullable=True),
        sa.Column("storage_ref", sa.Text(), nullable=True),
        sa.Column("sha256", sa.String(length=64), nullable=False),
        sa.Column("byte_size", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index(
        "ix_remediation_backup_artifacts_run_id",
        "remediation_backup_artifacts",
        ["remediation_run_id"],
    )
    op.create_index(
        "ix_remediation_backup_artifacts_host_id",
        "remediation_backup_artifacts",
        ["host_id"],
    )

    op.create_table(
        "maintenance_windows",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("site", sa.String(length=64), nullable=True),
        sa.Column("environment", sa.String(length=64), nullable=True),
        sa.Column("days_of_week", sa.String(length=32), nullable=False, server_default="0,1,2,3,4"),
        sa.Column("start_time", sa.String(length=8), nullable=False, server_default="00:00"),
        sa.Column("end_time", sa.String(length=8), nullable=False, server_default="23:59"),
        sa.Column("tz", sa.String(length=64), nullable=False, server_default="UTC"),
        sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_maintenance_windows_site", "maintenance_windows", ["site"])
    op.create_index("ix_maintenance_windows_environment", "maintenance_windows", ["environment"])


def downgrade() -> None:
    op.drop_index("ix_maintenance_windows_environment", table_name="maintenance_windows")
    op.drop_index("ix_maintenance_windows_site", table_name="maintenance_windows")
    op.drop_table("maintenance_windows")
    op.drop_index("ix_remediation_backup_artifacts_host_id", table_name="remediation_backup_artifacts")
    op.drop_index("ix_remediation_backup_artifacts_run_id", table_name="remediation_backup_artifacts")
    op.drop_table("remediation_backup_artifacts")
    op.drop_index("ix_remediation_runs_change_ticket", table_name="remediation_runs")
    op.drop_column("remediation_runs", "rollback_results_json")
    op.drop_column("remediation_runs", "backup_status")
    op.drop_column("remediation_runs", "change_ticket")
