"""task dead letters for Celery DLQ

Revision ID: 032_task_dead_letters
Revises: 031_notify_channel_owner
Create Date: 2026-07-27
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "032_task_dead_letters"
down_revision: Union[str, None] = "031_notify_channel_owner"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

deadletterstatus = postgresql.ENUM(
    "PENDING",
    "REPLAYED",
    "DISCARDED",
    name="deadletterstatus",
    create_type=False,
)


def upgrade() -> None:
    bind = op.get_bind()
    deadletterstatus.create(bind, checkfirst=True)
    op.create_table(
        "task_dead_letters",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("celery_task_id", sa.String(length=128), nullable=True),
        sa.Column("task_name", sa.String(length=256), nullable=False),
        sa.Column("queue", sa.String(length=64), nullable=False),
        sa.Column("args_json", sa.Text(), nullable=False, server_default="[]"),
        sa.Column("kwargs_json", sa.Text(), nullable=True),
        sa.Column("exception_type", sa.String(length=256), nullable=True),
        sa.Column("exception_message", sa.Text(), nullable=True),
        sa.Column("traceback_text", sa.Text(), nullable=True),
        sa.Column("retry_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("status", deadletterstatus, nullable=False, server_default="PENDING"),
        sa.Column("replay_task_id", sa.String(length=128), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("replayed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("discarded_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_task_dead_letters_celery_task_id", "task_dead_letters", ["celery_task_id"])
    op.create_index("ix_task_dead_letters_task_name", "task_dead_letters", ["task_name"])
    op.create_index("ix_task_dead_letters_queue", "task_dead_letters", ["queue"])
    op.create_index("ix_task_dead_letters_status", "task_dead_letters", ["status"])
    op.create_index(
        "ix_task_dead_letters_status_created",
        "task_dead_letters",
        ["status", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_task_dead_letters_status_created", table_name="task_dead_letters")
    op.drop_index("ix_task_dead_letters_status", table_name="task_dead_letters")
    op.drop_index("ix_task_dead_letters_queue", table_name="task_dead_letters")
    op.drop_index("ix_task_dead_letters_task_name", table_name="task_dead_letters")
    op.drop_index("ix_task_dead_letters_celery_task_id", table_name="task_dead_letters")
    op.drop_table("task_dead_letters")
    deadletterstatus.drop(op.get_bind(), checkfirst=True)
