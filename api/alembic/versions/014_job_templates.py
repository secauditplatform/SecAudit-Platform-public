"""job templates for compliance job presets

Revision ID: 014_job_templates
Revises: 013_scheduled_reports
Create Date: 2026-07-09
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "014_job_templates"
down_revision: Union[str, None] = "013_scheduled_reports"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

executiontype = postgresql.ENUM(
    "ssh",
    "powershell",
    "ansible",
    "python",
    name="executiontype",
    create_type=False,
)


def upgrade() -> None:
    op.create_table(
        "job_templates",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("standard_id", sa.Integer(), nullable=True),
        sa.Column("playbook_id", sa.Integer(), nullable=True),
        sa.Column("execution_type", executiontype, nullable=True),
        sa.Column("dynamic_filter", sa.JSON(), nullable=True),
        sa.Column("cron_expression", sa.String(length=128), nullable=True),
        sa.Column("is_scheduled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["playbook_id"], ["playbooks.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["standard_id"], ["standards.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "job_template_hosts",
        sa.Column("template_id", sa.Integer(), nullable=False),
        sa.Column("host_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["template_id"], ["job_templates.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("template_id", "host_id"),
    )


def downgrade() -> None:
    op.drop_table("job_template_hosts")
    op.drop_table("job_templates")
