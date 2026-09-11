"""task outbox for transactional Celery dispatch

Revision ID: 018_task_outbox
Revises: 017_inventory_scan_owner_sub
Create Date: 2026-07-12
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision: str = "018_task_outbox"
down_revision: Union[str, None] = "017_inventory_scan_owner_sub"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

outboxstatus = postgresql.ENUM(
    "PENDING",
    "SENT",
    "FAILED",
    name="outboxstatus",
    create_type=False,
)


def upgrade() -> None:
    bind = op.get_bind()
    outboxstatus.create(bind, checkfirst=True)
    op.create_table(
        "task_outbox",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("task_name", sa.String(length=256), nullable=False),
        sa.Column("args_json", sa.Text(), nullable=False),
        sa.Column("kwargs_json", sa.Text(), nullable=True),
        sa.Column("queue", sa.String(length=64), nullable=False),
        sa.Column("status", outboxstatus, nullable=False, server_default="PENDING"),
        sa.Column("callback_kind", sa.String(length=32), nullable=True),
        sa.Column("callback_ref_id", sa.Integer(), nullable=True),
        sa.Column("celery_task_id", sa.String(length=128), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_task_outbox_status_created", "task_outbox", ["status", "created_at"])


def downgrade() -> None:
    op.drop_index("ix_task_outbox_status_created", table_name="task_outbox")
    op.drop_table("task_outbox")
    outboxstatus.drop(op.get_bind(), checkfirst=True)
