"""Persist authorization scope for dynamic host targeting.

Revision ID: 026_dynamic_target_owner_scope
Revises: 025_fix_waiverstatus_enum_case
Create Date: 2026-07-17
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "026_dynamic_target_owner_scope"
down_revision: Union[str, None] = "025_fix_waiverstatus_enum_case"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    for table in ("jobs", "remediation_jobs"):
        op.add_column(
            table,
            sa.Column(
                "enforce_host_owner_scope",
                sa.Boolean(),
                nullable=False,
                server_default=sa.true(),
            ),
        )
        # Legacy ownerless objects are shared/administrative. Ownerful legacy
        # jobs are scoped fail-closed because their creator's role was not
        # persisted and cannot be reconstructed safely.
        op.execute(
            sa.text(
                f"UPDATE {table} "
                "SET enforce_host_owner_scope = false "
                "WHERE owner_sub IS NULL"
            )
        )


def downgrade() -> None:
    for table in ("remediation_jobs", "jobs"):
        op.drop_column(table, "enforce_host_owner_scope")
