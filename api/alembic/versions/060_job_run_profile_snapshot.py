"""Store the profile identity on a job run at the moment the worker starts it.

Revision ID: 060_job_run_profile_snapshot
Revises: 059_directory_sources
Create Date: 2026-10-08
"""

import sqlalchemy as sa
from alembic import op

revision = "060_job_run_profile_snapshot"
down_revision = "059_directory_sources"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("job_runs", sa.Column("profile_snapshot", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("job_runs", "profile_snapshot")
