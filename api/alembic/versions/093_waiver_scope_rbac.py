"""Waiver approval scope and operator site limits.

Revision ID: 093_waiver_scope_rbac
Revises: 092_skip_become
Create Date: 2026-11-24
"""

import sqlalchemy as sa

from alembic import op

revision = "093_waiver_scope_rbac"
down_revision = "092_skip_become"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(sa.text("ALTER TYPE userrole ADD VALUE IF NOT EXISTS 'SECURITY_APPROVER'"))
    op.add_column(
        "users",
        sa.Column("access_sites", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )
    op.add_column(
        "users",
        sa.Column("access_environments", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )
    op.add_column(
        "users",
        sa.Column("access_tags", sa.JSON(), nullable=False, server_default=sa.text("'[]'")),
    )
    op.add_column("compliance_waivers", sa.Column("scope_site", sa.String(length=64), nullable=True))
    op.add_column(
        "compliance_waivers", sa.Column("scope_environment", sa.String(length=64), nullable=True)
    )
    op.add_column("compliance_waivers", sa.Column("scope_tag", sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column("compliance_waivers", "scope_tag")
    op.drop_column("compliance_waivers", "scope_environment")
    op.drop_column("compliance_waivers", "scope_site")
    op.drop_column("users", "access_tags")
    op.drop_column("users", "access_environments")
    op.drop_column("users", "access_sites")
