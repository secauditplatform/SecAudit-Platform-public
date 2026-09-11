"""job baseline_run_id

Revision ID: 003_job_baseline_run
Revises: 002_host_group_members
Create Date: 2026-07-07

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "003_job_baseline_run"
down_revision: Union[str, None] = "002_host_group_members"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("jobs", sa.Column("baseline_run_id", sa.Integer(), nullable=True))
    op.create_foreign_key(
        "fk_jobs_baseline_run_id",
        "jobs",
        "job_runs",
        ["baseline_run_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint("fk_jobs_baseline_run_id", "jobs", type_="foreignkey")
    op.drop_column("jobs", "baseline_run_id")
