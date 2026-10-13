"""Audit Map layout, confirmed services, and check-together edges.

Revision ID: 062_audit_map
Revises: 061_snmp_discovery
Create Date: 2026-10-09
"""

import sqlalchemy as sa
from alembic import op

revision = "062_audit_map"
down_revision = "061_snmp_discovery"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_map_layouts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("owner_sub", sa.String(length=256), nullable=False),
        sa.Column("host_id", sa.Integer(), sa.ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("x", sa.Float(), nullable=False),
        sa.Column("y", sa.Float(), nullable=False),
        sa.UniqueConstraint("owner_sub", "host_id", name="uq_audit_map_layout_owner_host"),
    )
    op.create_index("ix_audit_map_layouts_owner_sub", "audit_map_layouts", ["owner_sub"])
    op.create_index("ix_audit_map_layouts_host_id", "audit_map_layouts", ["host_id"])

    op.create_table(
        "audit_map_services",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("host_id", sa.Integer(), sa.ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.UniqueConstraint("host_id", "port", name="uq_audit_map_service_host_port"),
    )
    op.create_index("ix_audit_map_services_host_id", "audit_map_services", ["host_id"])

    op.create_table(
        "audit_map_edges",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("source_host_id", sa.Integer(), sa.ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("source_port", sa.Integer(), nullable=False),
        sa.Column("target_host_id", sa.Integer(), sa.ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False),
        sa.Column("target_port", sa.Integer(), nullable=False),
        sa.Column("created_by", sa.String(length=256), nullable=True),
        sa.UniqueConstraint(
            "source_host_id",
            "source_port",
            "target_host_id",
            "target_port",
            name="uq_audit_map_edge_endpoints",
        ),
    )
    op.create_index("ix_audit_map_edges_source_host_id", "audit_map_edges", ["source_host_id"])
    op.create_index("ix_audit_map_edges_target_host_id", "audit_map_edges", ["target_host_id"])


def downgrade() -> None:
    op.drop_index("ix_audit_map_edges_target_host_id", table_name="audit_map_edges")
    op.drop_index("ix_audit_map_edges_source_host_id", table_name="audit_map_edges")
    op.drop_table("audit_map_edges")
    op.drop_index("ix_audit_map_services_host_id", table_name="audit_map_services")
    op.drop_table("audit_map_services")
    op.drop_index("ix_audit_map_layouts_host_id", table_name="audit_map_layouts")
    op.drop_index("ix_audit_map_layouts_owner_sub", table_name="audit_map_layouts")
    op.drop_table("audit_map_layouts")
