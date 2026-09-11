"""add standards.source_format and rules.scap_rule_id for SCAP/XCCDF import

Revision ID: 008_scap_xccdf
Revises: 007_audit_log
Create Date: 2026-07-08
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "008_scap_xccdf"
down_revision: Union[str, None] = "007_audit_log"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "standards",
        sa.Column("source_format", sa.String(length=32), nullable=False, server_default="custom"),
    )
    op.add_column(
        "rules",
        sa.Column("scap_rule_id", sa.String(length=256), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("rules", "scap_rule_id")
    op.drop_column("standards", "source_format")
