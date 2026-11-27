"""Add remediation_backup and remediation_restore script kinds.

Revision ID: 089_script_kind_backup_restore
Revises: 088_remediation_backup_mw
Create Date: 2026-11-14
"""

import sqlalchemy as sa
from alembic import op

revision = "089_script_kind_backup_restore"
down_revision = "088_remediation_backup_mw"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(sa.text("ALTER TYPE scriptkind ADD VALUE IF NOT EXISTS 'REMEDIATION_BACKUP'"))
    op.execute(sa.text("ALTER TYPE scriptkind ADD VALUE IF NOT EXISTS 'REMEDIATION_RESTORE'"))


def downgrade() -> None:
    # Postgres cannot drop enum values safely; leave labels in place.
    pass
