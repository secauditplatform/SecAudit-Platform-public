"""Fix waiverstatus enum labels to uppercase (match jobstatus / SQLAlchemy native enum).

Revision ID: 025_fix_waiverstatus_enum_case
Revises: 024_compliance_waivers
Create Date: 2026-07-15
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "025_fix_waiverstatus_enum_case"
down_revision: Union[str, None] = "024_compliance_waivers"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_RENAMES = (
    ("pending", "PENDING"),
    ("approved", "APPROVED"),
    ("rejected", "REJECTED"),
    ("expired", "EXPIRED"),
    ("revoked", "REVOKED"),
)


def _rename_if_needed(old: str, new: str) -> None:
    # Safe for both lowercase (pre-fix 024) and already-uppercase installs.
    op.execute(
        sa.text(
            f"""
            DO $$
            BEGIN
              IF EXISTS (
                SELECT 1 FROM pg_enum e
                JOIN pg_type t ON e.enumtypid = t.oid
                WHERE t.typname = 'waiverstatus' AND e.enumlabel = '{old}'
              ) AND NOT EXISTS (
                SELECT 1 FROM pg_enum e
                JOIN pg_type t ON e.enumtypid = t.oid
                WHERE t.typname = 'waiverstatus' AND e.enumlabel = '{new}'
              ) THEN
                ALTER TYPE waiverstatus RENAME VALUE '{old}' TO '{new}';
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
        "compliance_waivers",
        "status",
        server_default="PENDING",
        existing_nullable=False,
    )


def downgrade() -> None:
    for old, new in _RENAMES:
        _rename_if_needed(new, old)
    op.alter_column(
        "compliance_waivers",
        "status",
        server_default="pending",
        existing_nullable=False,
    )
