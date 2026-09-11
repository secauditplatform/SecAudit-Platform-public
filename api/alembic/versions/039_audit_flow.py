"""Add AuditFlow tables and Host.is_ephemeral.

Revision ID: 039_audit_flow
Revises: 038_pb_compliance_tpl
Create Date: 2026-08-14
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "039_audit_flow"
down_revision: Union[str, None] = "038_pb_compliance_tpl"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_AUDIT_FLOW_STATUS = postgresql.ENUM(
    "pending",
    "scanning",
    "ready",
    "running",
    "completed",
    "failed",
    "cancelled",
    name="auditflowstatus",
    create_type=False,
)

credentialtype = postgresql.ENUM(
    "SSH_PASSWORD",
    "SSH_KEY",
    "WINRM",
    "ANSIBLE_VAULT",
    name="credentialtype",
    create_type=False,
)


def upgrade() -> None:
    op.add_column(
        "hosts",
        sa.Column("is_ephemeral", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    bind = op.get_bind()
    _AUDIT_FLOW_STATUS.create(bind, checkfirst=True)
    op.create_table(
        "audit_flow_runs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("status", _AUDIT_FLOW_STATUS, nullable=False, server_default="pending"),
        sa.Column("targets_json", sa.JSON(), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("owner_sub", sa.String(length=256), nullable=True),
        sa.Column("hosts_found", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_audit_flow_runs_owner_sub", "audit_flow_runs", ["owner_sub"])
    op.create_table(
        "audit_flow_credentials",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("run_id", sa.Integer(), sa.ForeignKey("audit_flow_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("label", sa.String(length=128), nullable=False),
        sa.Column("credential_type", credentialtype, nullable=False),
        sa.Column("username", sa.String(length=128), nullable=False),
        sa.Column("encrypted_secret", sa.Text(), nullable=False),
    )
    op.create_index("ix_audit_flow_credentials_run_id", "audit_flow_credentials", ["run_id"])
    op.create_table(
        "audit_flow_hosts",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("run_id", sa.Integer(), sa.ForeignKey("audit_flow_runs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("hostname", sa.String(length=256), nullable=True),
        sa.Column("platform", sa.String(length=16), nullable=True),
        sa.Column("os_guess", sa.String(length=256), nullable=True),
        sa.Column("open_ports", sa.Text(), nullable=True),
        sa.Column("nmap_services", sa.Text(), nullable=True),
        sa.Column("credential_id", sa.Integer(), sa.ForeignKey("audit_flow_credentials.id", ondelete="SET NULL"), nullable=True),
        sa.Column("profile_id", sa.Integer(), sa.ForeignKey("profiles.id", ondelete="SET NULL"), nullable=True),
        sa.Column("profile_label", sa.String(length=256), nullable=True),
        sa.Column("confidence", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("alternatives_json", sa.JSON(), nullable=True),
        sa.Column("selected", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("skip_reason", sa.String(length=64), nullable=True),
        sa.Column("skip_detail", sa.Text(), nullable=True),
        sa.Column("ephemeral_host_id", sa.Integer(), sa.ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("ephemeral_credential_id", sa.Integer(), sa.ForeignKey("credentials.id", ondelete="SET NULL"), nullable=True),
        sa.Column("job_run_id", sa.Integer(), sa.ForeignKey("job_runs.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("run_id", "ip_address", name="uq_audit_flow_host_ip"),
    )
    op.create_index("ix_audit_flow_hosts_run_id", "audit_flow_hosts", ["run_id"])


def downgrade() -> None:
    op.drop_index("ix_audit_flow_hosts_run_id", table_name="audit_flow_hosts")
    op.drop_table("audit_flow_hosts")
    op.drop_index("ix_audit_flow_credentials_run_id", table_name="audit_flow_credentials")
    op.drop_table("audit_flow_credentials")
    op.drop_index("ix_audit_flow_runs_owner_sub", table_name="audit_flow_runs")
    op.drop_table("audit_flow_runs")
    bind = op.get_bind()
    _AUDIT_FLOW_STATUS.drop(bind, checkfirst=True)
    op.drop_column("hosts", "is_ephemeral")
