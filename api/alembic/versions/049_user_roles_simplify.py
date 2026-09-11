"""Migrate engineer/viewer users to operator and drop deprecated role labels.

Revision ID: 049_user_roles_simplify
Revises: 048_connectivity_playbook_winrm
Create Date: 2026-09-01
"""

from alembic import op

revision = "049_user_roles_simplify"
down_revision = "048_connectivity_playbook_winrm"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # PG native enum labels are uppercase (see 001_initial_schema).
    # Compare as text so deprecated labels do not need to be cast in WHERE.
    op.execute(
        "UPDATE users SET role = 'OPERATOR' "
        "WHERE role::text IN ('ENGINEER', 'VIEWER')"
    )

    # Recreate enum without ENGINEER/VIEWER (PG cannot DROP enum values directly).
    op.execute("ALTER TYPE userrole RENAME TO userrole_old")
    op.execute("CREATE TYPE userrole AS ENUM ('ADMIN', 'OPERATOR', 'AUDITOR')")
    op.execute("ALTER TABLE users ALTER COLUMN role DROP DEFAULT")
    op.execute(
        "ALTER TABLE users ALTER COLUMN role TYPE userrole "
        "USING role::text::userrole"
    )
    op.execute("ALTER TABLE users ALTER COLUMN role SET DEFAULT 'OPERATOR'")
    op.execute("DROP TYPE userrole_old")


def downgrade() -> None:
    op.execute("ALTER TYPE userrole RENAME TO userrole_new")
    op.execute(
        "CREATE TYPE userrole AS ENUM "
        "('ADMIN', 'ENGINEER', 'OPERATOR', 'AUDITOR', 'VIEWER')"
    )
    op.execute("ALTER TABLE users ALTER COLUMN role DROP DEFAULT")
    op.execute(
        "ALTER TABLE users ALTER COLUMN role TYPE userrole "
        "USING role::text::userrole"
    )
    op.execute("ALTER TABLE users ALTER COLUMN role SET DEFAULT 'VIEWER'")
    op.execute("DROP TYPE userrole_new")
