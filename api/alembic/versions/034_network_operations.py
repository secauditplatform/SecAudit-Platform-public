"""Revision ID: 034_network_operations
Revises: 033_playbook_owner
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "034_network_operations"
down_revision: Union[str, None] = "033_playbook_owner"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_JOB_SCOPE = postgresql.ENUM("standard", "network", name="jobscope", create_type=False)
_NETWORK_CHECK_MODE = postgresql.ENUM(
    "remote", "config_upload", "both", name="networkcheckmode", create_type=False
)
_NETWORK_VENDOR = postgresql.ENUM(
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
    "generic",
    name="networkvendor",
    create_type=False,
)


def upgrade() -> None:
    bind = op.get_bind()
    _JOB_SCOPE.create(bind, checkfirst=True)
    _NETWORK_CHECK_MODE.create(bind, checkfirst=True)
    _NETWORK_VENDOR.create(bind, checkfirst=True)

    op.add_column(
        "jobs",
        sa.Column("scope", _JOB_SCOPE, nullable=False, server_default="standard"),
    )
    op.add_column(
        "jobs",
        sa.Column("network_check_mode", _NETWORK_CHECK_MODE, nullable=True),
    )
    op.create_index("ix_jobs_scope", "jobs", ["scope"])

    op.add_column(
        "remediation_jobs",
        sa.Column("scope", _JOB_SCOPE, nullable=False, server_default="standard"),
    )
    op.create_index("ix_remediation_jobs_scope", "remediation_jobs", ["scope"])

    op.add_column(
        "playbooks",
        sa.Column("scope", _JOB_SCOPE, nullable=False, server_default="standard"),
    )
    op.create_index("ix_playbooks_scope", "playbooks", ["scope"])

    op.create_table(
        "network_device_configs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("job_id", sa.Integer(), sa.ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False),
        sa.Column("host_id", sa.Integer(), sa.ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("vendor", _NETWORK_VENDOR, nullable=False),
        sa.Column("filename", sa.String(length=512), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("owner_sub", sa.String(length=256), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_network_device_configs_job_id", "network_device_configs", ["job_id"])

    op.create_table(
        "network_remediation_configs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "remediation_run_id",
            sa.Integer(),
            sa.ForeignKey("remediation_runs.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("host_id", sa.Integer(), sa.ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("vendor", _NETWORK_VENDOR, nullable=False),
        sa.Column("filename", sa.String(length=512), nullable=False),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index(
        "ix_network_remediation_configs_run_id",
        "network_remediation_configs",
        ["remediation_run_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_network_remediation_configs_run_id", "network_remediation_configs")
    op.drop_table("network_remediation_configs")
    op.drop_index("ix_network_device_configs_job_id", "network_device_configs")
    op.drop_table("network_device_configs")
    op.drop_index("ix_playbooks_scope", "playbooks")
    op.drop_column("playbooks", "scope")
    op.drop_index("ix_remediation_jobs_scope", "remediation_jobs")
    op.drop_column("remediation_jobs", "scope")
    op.drop_index("ix_jobs_scope", "jobs")
    op.drop_column("jobs", "network_check_mode")
    op.drop_column("jobs", "scope")
    bind = op.get_bind()
    _NETWORK_VENDOR.drop(bind, checkfirst=True)
    _NETWORK_CHECK_MODE.drop(bind, checkfirst=True)
    _JOB_SCOPE.drop(bind, checkfirst=True)
