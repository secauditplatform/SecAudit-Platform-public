"""AuditFlow session templates with optional cron schedule.

Revision ID: 051_audit_flow_templates
Revises: 050_profile_name_encoding
Create Date: 2026-09-16
"""

from alembic import op
import sqlalchemy as sa

revision = "051_audit_flow_templates"
down_revision = "050_profile_name_encoding"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "audit_flow_templates",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("targets_json", sa.JSON(), nullable=False),
        sa.Column("credentials_json", sa.JSON(), nullable=False),
        sa.Column("save_to_inventory", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("cron_expression", sa.String(length=128), nullable=True),
        sa.Column("is_scheduled", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("last_scheduled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("owner_sub", sa.String(length=256), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.UniqueConstraint("name", name="uq_audit_flow_templates_name"),
    )
    op.create_index("ix_audit_flow_templates_owner_sub", "audit_flow_templates", ["owner_sub"])

    op.add_column(
        "audit_flow_runs",
        sa.Column("template_id", sa.Integer(), nullable=True),
    )
    op.create_foreign_key(
        "fk_audit_flow_runs_template_id",
        "audit_flow_runs",
        "audit_flow_templates",
        ["template_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_audit_flow_runs_template_id", "audit_flow_runs", ["template_id"])


def downgrade() -> None:
    op.drop_index("ix_audit_flow_runs_template_id", table_name="audit_flow_runs")
    op.drop_constraint("fk_audit_flow_runs_template_id", "audit_flow_runs", type_="foreignkey")
    op.drop_column("audit_flow_runs", "template_id")
    op.drop_index("ix_audit_flow_templates_owner_sub", table_name="audit_flow_templates")
    op.drop_table("audit_flow_templates")
