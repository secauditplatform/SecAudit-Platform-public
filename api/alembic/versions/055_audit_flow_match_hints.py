"""Store AuditFlow match explanation hints on discovered hosts.

Revision ID: 055_audit_flow_match_hints
Revises: 054_user_mfa_totp
Create Date: 2026-09-17
"""

from alembic import op
import sqlalchemy as sa

revision = "055_audit_flow_match_hints"
down_revision = "054_user_mfa_totp"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("audit_flow_hosts", sa.Column("match_hints_json", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("audit_flow_hosts", "match_hints_json")
