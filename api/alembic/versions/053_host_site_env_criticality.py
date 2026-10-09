"""Add host site, environment, and criticality columns.

Revision ID: 053_host_site_env_criticality
Revises: 052_waiver_change_ticket
Create Date: 2026-09-16
"""

from alembic import op
import sqlalchemy as sa

revision = "053_host_site_env_criticality"
down_revision = "052_waiver_change_ticket"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("hosts", sa.Column("site", sa.String(length=64), nullable=True))
    op.add_column("hosts", sa.Column("environment", sa.String(length=64), nullable=True))
    op.add_column("hosts", sa.Column("criticality", sa.String(length=32), nullable=True))
    op.create_index("ix_hosts_site", "hosts", ["site"])
    op.create_index("ix_hosts_environment", "hosts", ["environment"])
    op.create_index("ix_hosts_criticality", "hosts", ["criticality"])


def downgrade() -> None:
    op.drop_index("ix_hosts_criticality", table_name="hosts")
    op.drop_index("ix_hosts_environment", table_name="hosts")
    op.drop_index("ix_hosts_site", table_name="hosts")
    op.drop_column("hosts", "criticality")
    op.drop_column("hosts", "environment")
    op.drop_column("hosts", "site")
