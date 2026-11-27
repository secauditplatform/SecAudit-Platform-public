"""Index check_results.created_at for raw_output archival.

Revision ID: 090_check_results_created_at_idx
Revises: 089_script_kind_backup_restore
Create Date: 2026-11-22

Partitioning check_results by created_at is not done here: PostgreSQL unique
constraints on a partitioned table must include the partition key, and
uq_check_result_run_host_rule does not, so ON CONFLICT upserts would stop matching.
"""

from alembic import op

revision = "090_check_results_created_at_idx"
down_revision = "089_script_kind_backup_restore"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index("ix_check_results_created_at", "check_results", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_check_results_created_at", table_name="check_results")
