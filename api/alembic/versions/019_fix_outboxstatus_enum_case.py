"""Fix outboxstatus enum labels to uppercase (match jobstatus / SQLAlchemy native enum).

Preserves all existing task_outbox rows and IDs by renaming enum labels in place
(same pattern as 025_fix_waiverstatus_enum_case). Does not drop/recreate the table.

Rollout note: environments that already applied the historical drop/recreate variant of
this revision already lost any pre-019 outbox rows; this edit only protects upgrades
from pre-019. Do not add a destructive follow-up. Later revisions (027) add enum values
and columns additively and remain compatible with uppercase labels.

Revision ID: 019_fix_outboxstatus_enum_case
Revises: 018_task_outbox
Create Date: 2026-07-12
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "019_fix_outboxstatus_enum_case"
down_revision: Union[str, None] = "018_task_outbox"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_RENAMES = (
    ("pending", "PENDING"),
    ("sent", "SENT"),
    ("failed", "FAILED"),
)


def _rename_if_needed(old: str, new: str) -> None:
    # Safe for both lowercase (historical 018) and already-uppercase installs.
    op.execute(
        sa.text(
            f"""
            DO $$
            BEGIN
              IF EXISTS (
                SELECT 1 FROM pg_enum e
                JOIN pg_type t ON e.enumtypid = t.oid
                WHERE t.typname = 'outboxstatus' AND e.enumlabel = '{old}'
              ) AND NOT EXISTS (
                SELECT 1 FROM pg_enum e
                JOIN pg_type t ON e.enumtypid = t.oid
                WHERE t.typname = 'outboxstatus' AND e.enumlabel = '{new}'
              ) THEN
                ALTER TYPE outboxstatus RENAME VALUE '{old}' TO '{new}';
              END IF;
            END
            $$;
            """
        )
    )


def upgrade() -> None:
    for old, new in _RENAMES:
        _rename_if_needed(old, new)
    op.alter_column(
        "task_outbox",
        "status",
        server_default="PENDING",
        existing_nullable=False,
    )


def downgrade() -> None:
    for old, new in _RENAMES:
        _rename_if_needed(new, old)
    op.alter_column(
        "task_outbox",
        "status",
        server_default="pending",
        existing_nullable=False,
    )
