"""Normalize legacy profile_family tags to custom.

Revision ID: 036_normalize_profile_family
Revises: 035_rename_powershell_to_winrm
Create Date: 2026-08-07
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "036_normalize_profile_family"
down_revision: Union[str, None] = "035_rename_powershell_to_winrm"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        sa.text(
            """
            UPDATE profiles
            SET profile_family = 'custom'
            WHERE profile_family IS DISTINCT FROM 'custom'
            """
        )
    )


def downgrade() -> None:
    # Irreversible data normalization; no-op.
    pass
