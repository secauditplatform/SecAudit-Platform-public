"""Recreate compliance waivers with approval workflow.

Revision ID: 024_compliance_waivers
Revises: 023_scap_profiles
Create Date: 2026-07-15
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "024_compliance_waivers"
down_revision: Union[str, None] = "023_scap_profiles"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

WAIVER_STATUS = postgresql.ENUM(
    "PENDING",
    "APPROVED",
    "REJECTED",
    "EXPIRED",
    "REVOKED",
    name="waiverstatus",
    create_type=False,
)


def upgrade() -> None:
    bind = op.get_bind()
    postgresql.ENUM(
        "PENDING",
        "APPROVED",
        "REJECTED",
        "EXPIRED",
        "REVOKED",
        name="waiverstatus",
    ).create(bind, checkfirst=True)

    op.create_table(
        "compliance_waivers",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("standard_id", sa.Integer(), nullable=False),
        sa.Column("rule_tech_name", sa.String(length=64), nullable=False),
        sa.Column("host_id", sa.Integer(), nullable=True),
        sa.Column("job_id", sa.Integer(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("status", WAIVER_STATUS, server_default="PENDING", nullable=False),
        sa.Column("requested_by", sa.String(length=128), nullable=False),
        sa.Column("approved_by", sa.String(length=128), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rejected_by", sa.String(length=128), nullable=True),
        sa.Column("rejected_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column("owner_sub", sa.String(length=256), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"]),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"]),
        sa.ForeignKeyConstraint(["standard_id"], ["standards.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_compliance_waivers_standard_id", "compliance_waivers", ["standard_id"])
    op.create_index("ix_compliance_waivers_host_id", "compliance_waivers", ["host_id"])
    op.create_index("ix_compliance_waivers_job_id", "compliance_waivers", ["job_id"])
    op.create_index("ix_compliance_waivers_status", "compliance_waivers", ["status"])
    op.create_index("ix_compliance_waivers_active", "compliance_waivers", ["is_active"])
    op.create_index("ix_compliance_waivers_owner_sub", "compliance_waivers", ["owner_sub"])
    op.create_index("ix_compliance_waivers_expires_at", "compliance_waivers", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_compliance_waivers_expires_at", table_name="compliance_waivers")
    op.drop_index("ix_compliance_waivers_owner_sub", table_name="compliance_waivers")
    op.drop_index("ix_compliance_waivers_active", table_name="compliance_waivers")
    op.drop_index("ix_compliance_waivers_status", table_name="compliance_waivers")
    op.drop_index("ix_compliance_waivers_job_id", table_name="compliance_waivers")
    op.drop_index("ix_compliance_waivers_host_id", table_name="compliance_waivers")
    op.drop_index("ix_compliance_waivers_standard_id", table_name="compliance_waivers")
    op.drop_table("compliance_waivers")
    postgresql.ENUM(name="waiverstatus").drop(op.get_bind(), checkfirst=True)
