"""Add local-auth TOTP MFA columns to users.

Revision ID: 054_user_mfa_totp
Revises: 053_host_site_env_criticality
Create Date: 2026-09-17
"""

from alembic import op
import sqlalchemy as sa

revision = "054_user_mfa_totp"
down_revision = "053_host_site_env_criticality"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "mfa_enabled",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column("users", sa.Column("totp_secret_encrypted", sa.Text(), nullable=True))
    op.add_column("users", sa.Column("mfa_recovery_codes_json", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("users", "mfa_recovery_codes_json")
    op.drop_column("users", "totp_secret_encrypted")
    op.drop_column("users", "mfa_enabled")
