"""SNMP inventory discovery: credential types and scan method.

Revision ID: 061_snmp_discovery
Revises: 060_job_run_profile_snapshot
Create Date: 2026-10-08
"""

import sqlalchemy as sa
from alembic import op

revision = "061_snmp_discovery"
down_revision = "060_job_run_profile_snapshot"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TYPE credentialtype ADD VALUE IF NOT EXISTS 'SNMP_V2C'")
    op.execute("ALTER TYPE credentialtype ADD VALUE IF NOT EXISTS 'SNMP_V3'")
    op.add_column("credentials", sa.Column("snmp_priv_protocol", sa.String(length=32), nullable=True))
    op.add_column(
        "inventory_scans",
        sa.Column("method", sa.String(length=16), nullable=False, server_default="nmap"),
    )
    op.add_column("inventory_scans", sa.Column("credential_id", sa.Integer(), nullable=True))
    op.add_column("inventory_scans", sa.Column("snmp_port", sa.Integer(), nullable=True))
    op.create_foreign_key(
        "fk_inventory_scans_credential_id",
        "inventory_scans",
        "credentials",
        ["credential_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.add_column("inventory_scan_results", sa.Column("platform_hint", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("inventory_scan_results", "platform_hint")
    op.drop_constraint("fk_inventory_scans_credential_id", "inventory_scans", type_="foreignkey")
    op.drop_column("inventory_scans", "snmp_port")
    op.drop_column("inventory_scans", "credential_id")
    op.drop_column("inventory_scans", "method")
    op.drop_column("credentials", "snmp_priv_protocol")
