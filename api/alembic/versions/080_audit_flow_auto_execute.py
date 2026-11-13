"""AuditFlowTemplate.auto_execute for scheduled scan→audit.

Revision ID: 080_audit_flow_auto_execute
Revises: 079_rule_tech_name_256
Create Date: 2026-11-09
"""

import sqlalchemy as sa
from alembic import op

revision = "080_audit_flow_auto_execute"
down_revision = "079_rule_tech_name_256"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "audit_flow_templates",
        sa.Column("auto_execute", sa.Boolean(), nullable=False, server_default=sa.false()),
    )


def downgrade() -> None:
    op.drop_column("audit_flow_templates", "auto_execute")
