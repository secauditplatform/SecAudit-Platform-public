"""Privilege escalation fields on credentials.

Revision ID: 083_credential_become
Revises: 082_remediation_rule_scope
Create Date: 2026-11-13
"""

import sqlalchemy as sa
from alembic import op

revision = "083_credential_become"
down_revision = "082_remediation_rule_scope"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("credentials", sa.Column("become_method", sa.String(length=32), nullable=True))
    op.add_column("credentials", sa.Column("become_username", sa.String(length=128), nullable=True))
    op.add_column("credentials", sa.Column("encrypted_become_secret", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("credentials", "encrypted_become_secret")
    op.drop_column("credentials", "become_username")
    op.drop_column("credentials", "become_method")
