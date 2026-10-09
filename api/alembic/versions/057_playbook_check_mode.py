"""Store Ansible check-mode flag on job runs.

Revision ID: 057_playbook_check_mode
Revises: 056_api_keys
Create Date: 2026-09-23
"""

from alembic import op
import sqlalchemy as sa

revision = "057_playbook_check_mode"
down_revision = "056_api_keys"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "job_runs",
        sa.Column(
            "check_mode",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )


def downgrade() -> None:
    op.drop_column("job_runs", "check_mode")
