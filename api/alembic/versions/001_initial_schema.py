"""Initial schema: full SecAudit platform tables and PostgreSQL enums.

Revision ID: 001_initial
Revises:
Create Date: 2026-07-06

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

categorytype = postgresql.ENUM(
    "OS", "MIDDLEWARE", "NETWORK", "CONTAINER", "DATABASE", "WEB", "OTHER",
    name="categorytype",
    create_type=False,
)
executiontype = postgresql.ENUM(
    "SSH", "POWERSHELL", "ANSIBLE", "PYTHON",
    name="executiontype",
    create_type=False,
)
scriptkind = postgresql.ENUM(
    "AUDIT", "REMEDIATION",
    name="scriptkind",
    create_type=False,
)
checkstatus = postgresql.ENUM(
    "PASS", "FAIL", "SKIP", "ERROR", "PENDING",
    name="checkstatus",
    create_type=False,
)
jobstatus = postgresql.ENUM(
    "PENDING", "RUNNING", "COMPLETED", "FAILED", "CANCELLED",
    name="jobstatus",
    create_type=False,
)
userrole = postgresql.ENUM(
    "ADMIN", "ENGINEER", "OPERATOR", "AUDITOR", "VIEWER",
    name="userrole",
    create_type=False,
)
credentialtype = postgresql.ENUM(
    "SSH_PASSWORD", "SSH_KEY", "WINRM", "ANSIBLE_VAULT",
    name="credentialtype",
    create_type=False,
)


def upgrade() -> None:
    bind = op.get_bind()
    categorytype.create(bind, checkfirst=True)
    executiontype.create(bind, checkfirst=True)
    scriptkind.create(bind, checkfirst=True)
    checkstatus.create(bind, checkfirst=True)
    jobstatus.create(bind, checkfirst=True)
    userrole.create(bind, checkfirst=True)
    credentialtype.create(bind, checkfirst=True)

    op.create_table(
        "categories",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("slug", sa.String(length=128), nullable=False),
        sa.Column("category_type", categorytype, nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("parent_id", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["parent_id"], ["categories.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
        sa.UniqueConstraint("slug"),
    )

    op.create_table(
        "playbooks",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )

    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("username", sa.String(length=128), nullable=False),
        sa.Column("email", sa.String(length=256), nullable=False),
        sa.Column("hashed_password", sa.String(length=256), nullable=False),
        sa.Column("full_name", sa.String(length=256), nullable=True),
        sa.Column("role", userrole, nullable=False, server_default="VIEWER"),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
        sa.UniqueConstraint("username"),
    )

    op.create_table(
        "host_groups",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )

    op.create_table(
        "credentials",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("credential_type", credentialtype, nullable=False),
        sa.Column("username", sa.String(length=128), nullable=True),
        sa.Column("encrypted_secret", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )

    op.create_table(
        "standards",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("tech_name", sa.String(length=256), nullable=False),
        sa.Column("label", sa.String(length=256), nullable=False),
        sa.Column("version", sa.String(length=32), nullable=False, server_default="1.0.0"),
        sa.Column("summary", sa.Text(), nullable=True),
        sa.Column("category_id", sa.Integer(), nullable=True),
        sa.Column("package_path", sa.String(length=512), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["category_id"], ["categories.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("tech_name"),
    )

    op.create_table(
        "hosts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("hostname", sa.String(length=256), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False, server_default="22"),
        sa.Column("os_type", sa.String(length=64), nullable=True),
        sa.Column("credential_id", sa.Integer(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["credential_id"], ["credentials.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "inventory_scans",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("target", sa.String(length=256), nullable=False),
        sa.Column("status", jobstatus, nullable=False, server_default="PENDING"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("hosts_found", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("hosts_created", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("nmap_flags", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "check_scripts",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("standard_id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("execution_type", executiontype, nullable=False),
        sa.Column("script_file", sa.String(length=512), nullable=False),
        sa.Column("script_kind", scriptkind, nullable=False, server_default="AUDIT"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["standard_id"], ["standards.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "rules",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("standard_id", sa.Integer(), nullable=False),
        sa.Column("tech_name", sa.String(length=64), nullable=False),
        sa.Column("title", sa.String(length=512), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", sa.String(length=32), nullable=True),
        sa.ForeignKeyConstraint(["standard_id"], ["standards.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("standard_id", "tech_name", name="uq_standard_rule"),
    )

    op.create_table(
        "jobs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("standard_id", sa.Integer(), nullable=True),
        sa.Column("playbook_id", sa.Integer(), nullable=True),
        sa.Column("host_group_id", sa.Integer(), nullable=True),
        sa.Column("created_by_id", sa.Integer(), nullable=True),
        sa.Column("cron_expression", sa.String(length=128), nullable=True),
        sa.Column("execution_type", executiontype, nullable=True),
        sa.Column("is_scheduled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("last_scheduled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["host_group_id"], ["host_groups.id"]),
        sa.ForeignKeyConstraint(["playbook_id"], ["playbooks.id"]),
        sa.ForeignKeyConstraint(["standard_id"], ["standards.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "inventory_scan_results",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scan_id", sa.Integer(), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=False),
        sa.Column("resolved_hostname", sa.String(length=256), nullable=True),
        sa.Column("host_id", sa.Integer(), nullable=True),
        sa.Column("open_ports", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"]),
        sa.ForeignKeyConstraint(["scan_id"], ["inventory_scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "interpreter_rules",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("check_script_id", sa.Integer(), nullable=False),
        sa.Column("regex", sa.String(length=512), nullable=False),
        sa.Column("extraction_type", sa.String(length=32), nullable=False, server_default="SINGLE"),
        sa.Column("tech_name", sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(["check_script_id"], ["check_scripts.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "remediation_jobs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("name", sa.String(length=256), nullable=False),
        sa.Column("standard_id", sa.Integer(), nullable=False),
        sa.Column("remediation_script_id", sa.Integer(), nullable=True),
        sa.Column("execution_type", executiontype, nullable=False),
        sa.Column("cron_expression", sa.String(length=128), nullable=True),
        sa.Column("is_scheduled", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("last_scheduled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["remediation_script_id"], ["check_scripts.id"]),
        sa.ForeignKeyConstraint(["standard_id"], ["standards.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "job_hosts",
        sa.Column("job_id", sa.Integer(), nullable=False),
        sa.Column("host_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("job_id", "host_id"),
    )

    op.create_table(
        "job_runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("job_id", sa.Integer(), nullable=False),
        sa.Column("status", jobstatus, nullable=False, server_default="PENDING"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("celery_task_id", sa.String(length=64), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "remediation_job_hosts",
        sa.Column("remediation_job_id", sa.Integer(), nullable=False),
        sa.Column("host_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["remediation_job_id"], ["remediation_jobs.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("remediation_job_id", "host_id"),
    )

    op.create_table(
        "remediation_runs",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("remediation_job_id", sa.Integer(), nullable=False),
        sa.Column("status", jobstatus, nullable=False, server_default="PENDING"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("celery_task_id", sa.String(length=64), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["remediation_job_id"], ["remediation_jobs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "check_results",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("job_run_id", sa.Integer(), nullable=False),
        sa.Column("host_id", sa.Integer(), nullable=False),
        sa.Column("rule_tech_name", sa.String(length=64), nullable=False),
        sa.Column("status", checkstatus, nullable=False),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("raw_output", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"]),
        sa.ForeignKeyConstraint(["job_run_id"], ["job_runs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "remediation_results",
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("remediation_run_id", sa.Integer(), nullable=False),
        sa.Column("host_id", sa.Integer(), nullable=False),
        sa.Column("script_name", sa.String(length=256), nullable=False),
        sa.Column("status", checkstatus, nullable=False),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("raw_output", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()"), nullable=False),
        sa.ForeignKeyConstraint(["host_id"], ["hosts.id"]),
        sa.ForeignKeyConstraint(["remediation_run_id"], ["remediation_runs.id"]),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("remediation_results")
    op.drop_table("check_results")
    op.drop_table("remediation_runs")
    op.drop_table("remediation_job_hosts")
    op.drop_table("job_runs")
    op.drop_table("job_hosts")
    op.drop_table("remediation_jobs")
    op.drop_table("interpreter_rules")
    op.drop_table("inventory_scan_results")
    op.drop_table("jobs")
    op.drop_table("rules")
    op.drop_table("check_scripts")
    op.drop_table("inventory_scans")
    op.drop_table("hosts")
    op.drop_table("standards")
    op.drop_table("credentials")
    op.drop_table("host_groups")
    op.drop_table("users")
    op.drop_table("playbooks")
    op.drop_table("categories")

    bind = op.get_bind()
    credentialtype.drop(bind, checkfirst=True)
    userrole.drop(bind, checkfirst=True)
    jobstatus.drop(bind, checkfirst=True)
    checkstatus.drop(bind, checkfirst=True)
    scriptkind.drop(bind, checkfirst=True)
    executiontype.drop(bind, checkfirst=True)
    categorytype.drop(bind, checkfirst=True)
