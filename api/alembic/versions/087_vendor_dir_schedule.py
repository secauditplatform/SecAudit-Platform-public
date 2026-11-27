"""Host network vendor fields and DirectorySource schedule/lifecycle.

Revision ID: 087_vendor_dir_schedule
Revises: 086_report_scale_siem
Create Date: 2026-11-14
"""

import sqlalchemy as sa
from alembic import op

revision = "087_vendor_dir_schedule"
down_revision = "086_report_scale_siem"
branch_labels = None
depends_on = None

_NEW_VENDORS = ("eltex", "mikrotik", "usergate", "continent", "qtech")


def upgrade() -> None:
    for value in _NEW_VENDORS:
        op.execute(sa.text(f"ALTER TYPE networkvendor ADD VALUE IF NOT EXISTS '{value}'"))

    network_vendor = sa.Enum(
        "cisco_ios",
        "cisco_nxos",
        "cisco_asa",
        "juniper_junos",
        "arista_eos",
        "huawei",
        "h3c",
        "fortinet",
        "palo_alto",
        "check_point",
        "eltex",
        "mikrotik",
        "usergate",
        "continent",
        "qtech",
        "generic",
        name="networkvendor",
        create_type=False,
    )
    op.add_column("hosts", sa.Column("network_vendor", network_vendor, nullable=True))
    op.add_column("hosts", sa.Column("os_family", sa.String(length=32), nullable=True))

    op.add_column("directory_sources", sa.Column("cron_expression", sa.String(length=128), nullable=True))
    op.add_column(
        "directory_sources",
        sa.Column("is_scheduled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
    op.add_column("directory_sources", sa.Column("last_scheduled_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        "directory_sources",
        sa.Column("missing_host_policy", sa.String(length=16), nullable=False, server_default="none"),
    )


def downgrade() -> None:
    op.drop_column("directory_sources", "missing_host_policy")
    op.drop_column("directory_sources", "last_scheduled_at")
    op.drop_column("directory_sources", "is_scheduled")
    op.drop_column("directory_sources", "cron_expression")
    op.drop_column("hosts", "os_family")
    op.drop_column("hosts", "network_vendor")
