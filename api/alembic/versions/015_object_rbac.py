"""object rbac owner_sub on hosts, jobs, remediation_jobs, job_templates

Revision ID: 015_object_rbac
Revises: 014_job_templates
Create Date: 2026-07-09
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "015_object_rbac"
down_revision: Union[str, None] = "014_job_templates"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    for table in ("hosts", "jobs", "remediation_jobs", "job_templates"):
        op.add_column(table, sa.Column("owner_sub", sa.String(length=256), nullable=True))
        op.create_index(f"ix_{table}_owner_sub", table, ["owner_sub"])


def downgrade() -> None:
    for table in ("job_templates", "remediation_jobs", "jobs", "hosts"):
        op.drop_index(f"ix_{table}_owner_sub", table_name=table)
        op.drop_column(table, "owner_sub")
