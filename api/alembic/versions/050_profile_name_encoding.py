"""Rename Profile.tech_name to profile_name; drop label; encoding meta.

Revision ID: 050_profile_name_encoding
Revises: 049_user_roles_simplify
Create Date: 2026-09-07
"""

from alembic import op
import sqlalchemy as sa

revision = "050_profile_name_encoding"
down_revision = "049_user_roles_simplify"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # profiles.tech_name -> profile_name
    op.alter_column(
        "profiles",
        "tech_name",
        new_column_name="profile_name",
        existing_type=sa.String(length=256),
        existing_nullable=False,
    )
    # Best-effort rename of the default unique index/constraint name from tech_name.
    op.execute(
        "ALTER INDEX IF EXISTS profiles_tech_name_key RENAME TO profiles_profile_name_key"
    )
    # Drop display-only label; profile_name is the single identity/display field.
    op.drop_column("profiles", "label")

    # Normalize default package versions stored as 1.0.0
    op.execute("UPDATE profiles SET version = '1.0' WHERE version = '1.0.0'")

    # audit_flow_hosts.profile_label -> profile_name (denormalized Profile display)
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {col["name"] for col in inspector.get_columns("audit_flow_hosts")}
    if "profile_label" in columns:
        op.alter_column(
            "audit_flow_hosts",
            "profile_label",
            new_column_name="profile_name",
            existing_type=sa.String(length=256),
            existing_nullable=True,
        )


def downgrade() -> None:
    bind = op.get_bind()
    inspector = sa.inspect(bind)
    columns = {col["name"] for col in inspector.get_columns("audit_flow_hosts")}
    if "profile_name" in columns and "profile_label" not in columns:
        op.alter_column(
            "audit_flow_hosts",
            "profile_name",
            new_column_name="profile_label",
            existing_type=sa.String(length=256),
            existing_nullable=True,
        )

    op.add_column(
        "profiles",
        sa.Column("label", sa.String(length=256), nullable=False, server_default=""),
    )
    op.execute("UPDATE profiles SET label = profile_name")
    op.alter_column("profiles", "label", server_default=None)
    op.alter_column(
        "profiles",
        "profile_name",
        new_column_name="tech_name",
        existing_type=sa.String(length=256),
        existing_nullable=False,
    )
    op.execute(
        "ALTER INDEX IF EXISTS profiles_profile_name_key RENAME TO profiles_tech_name_key"
    )
