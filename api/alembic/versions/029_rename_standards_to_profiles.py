"""Rename standards table/columns to profiles.

Revision ID: 029_rename_standards_to_profiles
Revises: 028_fk_idx_delivery
Create Date: 2026-07-20
"""

from typing import Sequence, Union

from alembic import op

revision: str = "029_rename_standards_to_profiles"
down_revision: Union[str, None] = "028_fk_idx_delivery"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_TABLES_WITH_STANDARD_ID = (
    "check_scripts",
    "rules",
    "jobs",
    "compliance_waivers",
    "remediation_jobs",
    "job_templates",
)


def upgrade() -> None:
    # PostgreSQL updates FK targets on table/column rename; we also rename
    # constraint/index names for consistency with the ORM.
    op.execute("ALTER TABLE standards RENAME TO profiles")

    for table in _TABLES_WITH_STANDARD_ID:
        op.execute(f"ALTER TABLE {table} RENAME COLUMN standard_id TO profile_id")
        op.execute(
            f"ALTER TABLE {table} RENAME CONSTRAINT {table}_standard_id_fkey "
            f"TO {table}_profile_id_fkey"
        )

    op.execute("ALTER TABLE rules RENAME CONSTRAINT uq_standard_rule TO uq_profile_rule")
    op.execute(
        "ALTER INDEX ix_compliance_waivers_standard_id "
        "RENAME TO ix_compliance_waivers_profile_id"
    )


def downgrade() -> None:
    op.execute(
        "ALTER INDEX ix_compliance_waivers_profile_id "
        "RENAME TO ix_compliance_waivers_standard_id"
    )
    op.execute("ALTER TABLE rules RENAME CONSTRAINT uq_profile_rule TO uq_standard_rule")

    for table in _TABLES_WITH_STANDARD_ID:
        op.execute(
            f"ALTER TABLE {table} RENAME CONSTRAINT {table}_profile_id_fkey "
            f"TO {table}_standard_id_fkey"
        )
        op.execute(f"ALTER TABLE {table} RENAME COLUMN profile_id TO standard_id")

    op.execute("ALTER TABLE profiles RENAME TO standards")
