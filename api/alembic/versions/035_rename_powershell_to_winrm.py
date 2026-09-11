"""Rename executiontype POWERSHELL to WINRM.

Revision ID: 035_rename_powershell_to_winrm
Revises: 034_network_operations
Create Date: 2026-07-29
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "035_rename_powershell_to_winrm"
down_revision: Union[str, None] = "034_network_operations"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _rename_enum_value(old: str, new: str) -> None:
    op.execute(
        sa.text(
            f"""
            DO $$
            BEGIN
              IF EXISTS (
                SELECT 1 FROM pg_enum e
                JOIN pg_type t ON e.enumtypid = t.oid
                WHERE t.typname = 'executiontype' AND e.enumlabel = '{old}'
              ) AND NOT EXISTS (
                SELECT 1 FROM pg_enum e
                JOIN pg_type t ON e.enumtypid = t.oid
                WHERE t.typname = 'executiontype' AND e.enumlabel = '{new}'
              ) THEN
                ALTER TYPE executiontype RENAME VALUE '{old}' TO '{new}';
              END IF;
            END
            $$;
            """
        )
    )


def upgrade() -> None:
    _rename_enum_value("POWERSHELL", "WINRM")


def downgrade() -> None:
    _rename_enum_value("WINRM", "POWERSHELL")
