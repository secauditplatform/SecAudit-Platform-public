from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    JSON,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from secaudit_core.base import Base
from secaudit_core.enums import (
    AuditFlowStatus,
    CategoryType,
    CheckStatus,
    CredentialType,
    ExecutionType,
    JobScope,
    JobStatus,
    NetworkCheckMode,
    NetworkVendor,
    NotificationChannelType,
    OutboxStatus,
    DeadLetterStatus,
    PlaybookKind,
    ScriptKind,
    UserRole,
    ScheduledReportDelivery,
    ScheduledReportFormat,
    WaiverStatus,
)

# PostgreSQL native enum type names (lowercase, matching SQLAlchemy defaults).
_PG_ENUM_KW = {"native_enum": True}


def _pg_str_enum(enum_cls, name: str) -> Enum:
    return Enum(
        enum_cls,
        name=name,
        values_callable=lambda choices: [item.value for item in choices],
        create_constraint=False,
        native_enum=True,
    )


class Category(Base):
    __tablename__ = "categories"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    slug: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    category_type: Mapped[CategoryType] = mapped_column(
        Enum(CategoryType, name="categorytype", **_PG_ENUM_KW), nullable=False
    )
    description: Mapped[str | None] = mapped_column(Text)
    parent_id: Mapped[int | None] = mapped_column(ForeignKey("categories.id"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    parent: Mapped["Category | None"] = relationship(remote_side=[id], back_populates="children")
    children: Mapped[list["Category"]] = relationship(back_populates="parent")
    profiles: Mapped[list["Profile"]] = relationship(back_populates="category")


class Profile(Base):
    __tablename__ = "profiles"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    profile_name: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)
    version: Mapped[str] = mapped_column(String(32), default="1.0")
    summary: Mapped[str | None] = mapped_column(Text)
    category_id: Mapped[int | None] = mapped_column(ForeignKey("categories.id"))
    package_path: Mapped[str | None] = mapped_column(String(512))
    source_format: Mapped[str] = mapped_column(String(32), default="custom", nullable=False)
    profile_family: Mapped[str | None] = mapped_column(String(32))
    scap_profile_id: Mapped[str | None] = mapped_column(String(256))
    profile_title: Mapped[str | None] = mapped_column(String(512))
    benchmark_ref: Mapped[str | None] = mapped_column(String(512))
    os_name: Mapped[str | None] = mapped_column(String(128))
    os_version: Mapped[str | None] = mapped_column(String(64))
    os_vendor: Mapped[str | None] = mapped_column(String(128))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    category: Mapped["Category | None"] = relationship(back_populates="profiles")
    check_scripts: Mapped[list["CheckScript"]] = relationship(back_populates="profile")
    rules: Mapped[list["Rule"]] = relationship(back_populates="profile")
    remediation_jobs: Mapped[list["RemediationJob"]] = relationship(back_populates="profile")
    compliance_playbooks: Mapped[list["Playbook"]] = relationship(back_populates="profile")


class CheckScript(Base):
    __tablename__ = "check_scripts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    profile_id: Mapped[int] = mapped_column(ForeignKey("profiles.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    execution_type: Mapped[ExecutionType] = mapped_column(
        Enum(ExecutionType, name="executiontype", **_PG_ENUM_KW), nullable=False
    )
    script_file: Mapped[str] = mapped_column(String(512), nullable=False)
    script_kind: Mapped[ScriptKind] = mapped_column(
        Enum(ScriptKind, name="scriptkind", **_PG_ENUM_KW),
        default=ScriptKind.AUDIT,
        nullable=False,
    )
    description: Mapped[str | None] = mapped_column(Text)

    profile: Mapped["Profile"] = relationship(back_populates="check_scripts")
    interpreter_rules: Mapped[list["InterpreterRule"]] = relationship(back_populates="check_script")


class Rule(Base):
    """Profile check metadata. Not used for output parsing — see InterpreterRule."""

    __tablename__ = "rules"
    __table_args__ = (UniqueConstraint("profile_id", "tech_name", name="uq_profile_rule"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    profile_id: Mapped[int] = mapped_column(ForeignKey("profiles.id"), nullable=False)
    tech_name: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str | None] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str | None] = mapped_column(String(32))
    scap_rule_id: Mapped[str | None] = mapped_column(String(256))

    profile: Mapped["Profile"] = relationship(back_populates="rules")


class InterpreterRule(Base):
    __tablename__ = "interpreter_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    check_script_id: Mapped[int] = mapped_column(ForeignKey("check_scripts.id"), nullable=False)
    regex: Mapped[str] = mapped_column(String(512), nullable=False)
    extraction_type: Mapped[str] = mapped_column(String(32), default="SINGLE")
    tech_name: Mapped[str] = mapped_column(String(64), nullable=False)

    check_script: Mapped["CheckScript"] = relationship(back_populates="interpreter_rules")


class User(Base):
    """Platform users for local authentication (managed via /users admin API)."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(256), nullable=False)
    full_name: Mapped[str | None] = mapped_column(String(256))
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, name="userrole", **_PG_ENUM_KW), default=UserRole.OPERATOR
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    actor_username: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_roles: Mapped[list[str] | None] = mapped_column(JSON)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(128))
    resource_name: Mapped[str | None] = mapped_column(String(256))
    outcome: Mapped[str] = mapped_column(String(32), default="success", nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(512))
    metadata_json: Mapped[dict | None] = mapped_column(JSON)


class NotificationChannel(Base):
    __tablename__ = "notification_channels"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    channel_type: Mapped[NotificationChannelType] = mapped_column(
        _pg_str_enum(NotificationChannelType, "notificationchanneltype"),
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    events: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    config_json: Mapped[dict | None] = mapped_column(JSON)
    encrypted_secret: Mapped[str | None] = mapped_column(Text)
    owner_sub: Mapped[str | None] = mapped_column(String(256), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class Credential(Base):
    __tablename__ = "credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    credential_type: Mapped[CredentialType] = mapped_column(
        Enum(CredentialType, name="credentialtype", **_PG_ENUM_KW), nullable=False
    )
    username: Mapped[str | None] = mapped_column(String(128))
    encrypted_secret: Mapped[str] = mapped_column(Text, nullable=False)
    encrypted_key_passphrase: Mapped[str | None] = mapped_column(Text)
    service_username: Mapped[str | None] = mapped_column(String(128))
    encrypted_service_secret: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    owner_sub: Mapped[str | None] = mapped_column(String(256), index=True)
    is_ephemeral: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    hostname: Mapped[str] = mapped_column(String(256), nullable=False)
    port: Mapped[int] = mapped_column(Integer, default=22)
    os_type: Mapped[str | None] = mapped_column(String(64))
    credential_id: Mapped[int | None] = mapped_column(ForeignKey("credentials.id", ondelete="SET NULL"))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_ephemeral: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    owner_sub: Mapped[str | None] = mapped_column(String(256), index=True)
    ssh_host_key_fingerprint: Mapped[str | None] = mapped_column(String(128))
    ssh_known_hosts_entry: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    credential: Mapped["Credential | None"] = relationship()
    credential_links: Mapped[list["HostCredentialLink"]] = relationship(
        back_populates="host", cascade="all, delete-orphan"
    )
    tags: Mapped[list["HostTagLink"]] = relationship(
        back_populates="host", cascade="all, delete-orphan"
    )


class InventoryScan(Base):
    __tablename__ = "inventory_scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[JobStatus] = mapped_column(
        Enum(JobStatus, name="jobstatus", **_PG_ENUM_KW), default=JobStatus.PENDING
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    error_message: Mapped[str | None] = mapped_column(Text)
    hosts_found: Mapped[int] = mapped_column(Integer, default=0)
    hosts_created: Mapped[int] = mapped_column(Integer, default=0)
    nmap_flags: Mapped[str | None] = mapped_column(Text)
    owner_sub: Mapped[str | None] = mapped_column(String(256), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    results: Mapped[list["InventoryScanResult"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )


class InventoryScanResult(Base):
    __tablename__ = "inventory_scan_results"
    __table_args__ = (UniqueConstraint("scan_id", "ip_address", name="uq_inventory_scan_result"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("inventory_scans.id", ondelete="CASCADE"), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    resolved_hostname: Mapped[str | None] = mapped_column(String(256))
    host_id: Mapped[int | None] = mapped_column(ForeignKey("hosts.id"))
    open_ports: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    scan: Mapped["InventoryScan"] = relationship(back_populates="results")
    host: Mapped["Host | None"] = relationship()


class TaskOutbox(Base):
    __tablename__ = "task_outbox"
    __table_args__ = (
        UniqueConstraint("celery_task_id", name="uq_task_outbox_celery_task_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    task_name: Mapped[str] = mapped_column(String(256), nullable=False)
    args_json: Mapped[str] = mapped_column(Text, nullable=False)
    kwargs_json: Mapped[str | None] = mapped_column(Text)
    queue: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[OutboxStatus] = mapped_column(
        Enum(OutboxStatus, name="outboxstatus", **_PG_ENUM_KW), default=OutboxStatus.PENDING
    )
    callback_kind: Mapped[str | None] = mapped_column(String(32))
    callback_ref_id: Mapped[int | None] = mapped_column(Integer)
    celery_task_id: Mapped[str | None] = mapped_column(String(128))
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    dispatch_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TaskDeadLetter(Base):
    __tablename__ = "task_dead_letters"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    celery_task_id: Mapped[str | None] = mapped_column(String(128), index=True)
    task_name: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    queue: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    args_json: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    kwargs_json: Mapped[str | None] = mapped_column(Text)
    exception_type: Mapped[str | None] = mapped_column(String(256))
    exception_message: Mapped[str | None] = mapped_column(Text)
    traceback_text: Mapped[str | None] = mapped_column(Text)
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[DeadLetterStatus] = mapped_column(
        Enum(DeadLetterStatus, name="deadletterstatus", **_PG_ENUM_KW),
        default=DeadLetterStatus.PENDING,
        index=True,
    )
    replay_task_id: Mapped[str | None] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    replayed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    discarded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class HostCredentialLink(Base):
    __tablename__ = "host_credentials"

    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), primary_key=True)
    credential_id: Mapped[int] = mapped_column(
        ForeignKey("credentials.id", ondelete="CASCADE"), primary_key=True
    )
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    host: Mapped["Host"] = relationship(back_populates="credential_links")
    credential: Mapped["Credential"] = relationship()


class HostTag(Base):
    __tablename__ = "host_tags"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    hosts: Mapped[list["HostTagLink"]] = relationship(
        back_populates="tag", cascade="all, delete-orphan"
    )


class HostTagLink(Base):
    __tablename__ = "host_tag_links"

    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), primary_key=True)
    tag_id: Mapped[int] = mapped_column(ForeignKey("host_tags.id", ondelete="CASCADE"), primary_key=True)

    host: Mapped["Host"] = relationship(back_populates="tags")
    tag: Mapped["HostTag"] = relationship(back_populates="hosts")


class Playbook(Base):
    __tablename__ = "playbooks"
    __table_args__ = (
        Index(
            "uq_playbooks_compliance_profile",
            "profile_id",
            unique=True,
            postgresql_where=text("kind = 'compliance_template' AND profile_id IS NOT NULL"),
            sqlite_where=text("kind = 'compliance_template' AND profile_id IS NOT NULL"),
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(256), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    owner_sub: Mapped[str | None] = mapped_column(String(256), index=True)
    kind: Mapped[PlaybookKind] = mapped_column(
        _pg_str_enum(PlaybookKind, "playbookkind"),
        default=PlaybookKind.USER,
        nullable=False,
    )
    profile_id: Mapped[int | None] = mapped_column(
        ForeignKey("profiles.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    version: Mapped[str] = mapped_column(String(32), default="1.0", nullable=False)
    scope: Mapped[JobScope] = mapped_column(
        _pg_str_enum(JobScope, "jobscope"),
        default=JobScope.STANDARD,
        nullable=False,
    )
    # linux | windows | network — UI platform tab (orthogonal to JobScope for standard).
    platform: Mapped[str] = mapped_column(String(16), default="linux", nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    profile: Mapped["Profile | None"] = relationship(back_populates="compliance_playbooks")


class Job(Base):
    __tablename__ = "jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    profile_id: Mapped[int | None] = mapped_column(ForeignKey("profiles.id"), nullable=True)
    playbook_id: Mapped[int | None] = mapped_column(ForeignKey("playbooks.id"), nullable=True)
    created_by_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"))
    owner_sub: Mapped[str | None] = mapped_column(String(256), index=True)
    enforce_host_owner_scope: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    cron_expression: Mapped[str | None] = mapped_column(String(128))
    execution_type: Mapped[ExecutionType | None] = mapped_column(
        Enum(ExecutionType, name="executiontype", create_constraint=False, native_enum=True),
        nullable=True,
    )
    dynamic_filter: Mapped[dict | None] = mapped_column(JSON)
    is_scheduled: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_scheduled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    baseline_run_id: Mapped[int | None] = mapped_column(ForeignKey("job_runs.id", ondelete="SET NULL"))
    webhook_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    encrypted_webhook_url: Mapped[str | None] = mapped_column(Text)
    webhook_events: Mapped[list | None] = mapped_column(JSON)
    scope: Mapped[JobScope] = mapped_column(
        _pg_str_enum(JobScope, "jobscope"),
        default=JobScope.STANDARD,
        nullable=False,
    )
    network_check_mode: Mapped[NetworkCheckMode | None] = mapped_column(
        _pg_str_enum(NetworkCheckMode, "networkcheckmode"),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    profile: Mapped["Profile"] = relationship()
    baseline_run: Mapped["JobRun | None"] = relationship(foreign_keys=[baseline_run_id])
    runs: Mapped[list["JobRun"]] = relationship(
        back_populates="job",
        foreign_keys="JobRun.job_id",
    )
    job_hosts: Mapped[list["JobHost"]] = relationship(back_populates="job", cascade="all, delete-orphan")


class JobHost(Base):
    __tablename__ = "job_hosts"

    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id", ondelete="CASCADE"), primary_key=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), primary_key=True)

    job: Mapped["Job"] = relationship(back_populates="job_hosts")
    host: Mapped["Host"] = relationship()


class JobRun(Base):
    __tablename__ = "job_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id"), nullable=False, index=True)
    status: Mapped[JobStatus] = mapped_column(
        Enum(JobStatus, name="jobstatus", create_constraint=False, native_enum=True),
        default=JobStatus.PENDING,
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    celery_task_id: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    job: Mapped["Job"] = relationship(back_populates="runs", foreign_keys=[job_id])
    check_results: Mapped[list["CheckResult"]] = relationship(back_populates="job_run")


class CheckResult(Base):
    __tablename__ = "check_results"
    __table_args__ = (
        UniqueConstraint(
            "job_run_id",
            "host_id",
            "rule_tech_name",
            name="uq_check_result_run_host_rule",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_run_id: Mapped[int] = mapped_column(ForeignKey("job_runs.id"), nullable=False, index=True)
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"), nullable=False, index=True)
    rule_tech_name: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[CheckStatus] = mapped_column(
        Enum(CheckStatus, name="checkstatus", **_PG_ENUM_KW), nullable=False
    )
    message: Mapped[str | None] = mapped_column(Text)
    raw_output: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    job_run: Mapped["JobRun"] = relationship(back_populates="check_results")
    host: Mapped["Host"] = relationship()


class ComplianceWaiver(Base):
    __tablename__ = "compliance_waivers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    profile_id: Mapped[int] = mapped_column(ForeignKey("profiles.id"), nullable=False, index=True)
    rule_tech_name: Mapped[str] = mapped_column(String(64), nullable=False)
    host_id: Mapped[int | None] = mapped_column(ForeignKey("hosts.id"), nullable=True, index=True)
    job_id: Mapped[int | None] = mapped_column(ForeignKey("jobs.id"), nullable=True, index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[WaiverStatus] = mapped_column(
        Enum(WaiverStatus, name="waiverstatus", **_PG_ENUM_KW),
        nullable=False,
        default=WaiverStatus.PENDING,
        index=True,
    )
    requested_by: Mapped[str] = mapped_column(String(128), nullable=False)
    approved_by: Mapped[str | None] = mapped_column(String(128))
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rejected_by: Mapped[str | None] = mapped_column(String(128))
    rejected_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rejection_reason: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    owner_sub: Mapped[str | None] = mapped_column(String(256), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    profile: Mapped["Profile"] = relationship()
    host: Mapped["Host | None"] = relationship()
    job: Mapped["Job | None"] = relationship()


class RemediationJob(Base):
    __tablename__ = "remediation_jobs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    profile_id: Mapped[int] = mapped_column(ForeignKey("profiles.id"), nullable=False)
    remediation_script_id: Mapped[int | None] = mapped_column(ForeignKey("check_scripts.id"), nullable=True)
    execution_type: Mapped[ExecutionType] = mapped_column(
        Enum(ExecutionType, name="executiontype", create_constraint=False, native_enum=True),
        nullable=False,
    )
    dynamic_filter: Mapped[dict | None] = mapped_column(JSON)
    cron_expression: Mapped[str | None] = mapped_column(String(128))
    is_scheduled: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_scheduled_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    owner_sub: Mapped[str | None] = mapped_column(String(256), index=True)
    enforce_host_owner_scope: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    webhook_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    encrypted_webhook_url: Mapped[str | None] = mapped_column(Text)
    webhook_events: Mapped[list | None] = mapped_column(JSON)
    scope: Mapped[JobScope] = mapped_column(
        _pg_str_enum(JobScope, "jobscope"),
        default=JobScope.STANDARD,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    profile: Mapped["Profile"] = relationship(back_populates="remediation_jobs")
    remediation_script: Mapped["CheckScript | None"] = relationship()
    runs: Mapped[list["RemediationRun"]] = relationship(back_populates="remediation_job")
    job_hosts: Mapped[list["RemediationJobHost"]] = relationship(
        back_populates="remediation_job", cascade="all, delete-orphan"
    )


class RemediationJobHost(Base):
    __tablename__ = "remediation_job_hosts"

    remediation_job_id: Mapped[int] = mapped_column(
        ForeignKey("remediation_jobs.id", ondelete="CASCADE"), primary_key=True
    )
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), primary_key=True)

    remediation_job: Mapped["RemediationJob"] = relationship(back_populates="job_hosts")
    host: Mapped["Host"] = relationship()


class RemediationRun(Base):
    __tablename__ = "remediation_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    remediation_job_id: Mapped[int] = mapped_column(
        ForeignKey("remediation_jobs.id"), nullable=False, index=True
    )
    status: Mapped[JobStatus] = mapped_column(
        Enum(JobStatus, name="jobstatus", create_constraint=False, native_enum=True),
        default=JobStatus.PENDING,
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    celery_task_id: Mapped[str | None] = mapped_column(String(64))
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    remediation_job: Mapped["RemediationJob"] = relationship(back_populates="runs")
    results: Mapped[list["RemediationResult"]] = relationship(back_populates="remediation_run")


class RemediationResult(Base):
    __tablename__ = "remediation_results"
    __table_args__ = (
        UniqueConstraint(
            "remediation_run_id",
            "host_id",
            "script_name",
            name="uq_remediation_result_run_host_script",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    remediation_run_id: Mapped[int] = mapped_column(
        ForeignKey("remediation_runs.id"), nullable=False, index=True
    )
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id"), nullable=False, index=True)
    script_name: Mapped[str] = mapped_column(String(256), nullable=False)
    status: Mapped[CheckStatus] = mapped_column(
        Enum(CheckStatus, name="checkstatus", create_constraint=False, native_enum=True),
        nullable=False,
    )
    message: Mapped[str | None] = mapped_column(Text)
    raw_output: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    remediation_run: Mapped["RemediationRun"] = relationship(back_populates="results")
    host: Mapped["Host"] = relationship()


class NetworkDeviceConfig(Base):
    __tablename__ = "network_device_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False, index=True)
    host_id: Mapped[int | None] = mapped_column(ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True)
    vendor: Mapped[NetworkVendor] = mapped_column(
        _pg_str_enum(NetworkVendor, "networkvendor"),
        nullable=False,
    )
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    owner_sub: Mapped[str | None] = mapped_column(String(256), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    job: Mapped["Job"] = relationship()
    host: Mapped["Host | None"] = relationship()


class NetworkRemediationConfig(Base):
    __tablename__ = "network_remediation_configs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    remediation_run_id: Mapped[int] = mapped_column(
        ForeignKey("remediation_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    host_id: Mapped[int | None] = mapped_column(ForeignKey("hosts.id", ondelete="SET NULL"), nullable=True)
    vendor: Mapped[NetworkVendor] = mapped_column(
        _pg_str_enum(NetworkVendor, "networkvendor"),
        nullable=False,
    )
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    remediation_run: Mapped["RemediationRun"] = relationship()
    host: Mapped["Host | None"] = relationship()


class ScheduledReport(Base):
    __tablename__ = "scheduled_reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    job_id: Mapped[int] = mapped_column(ForeignKey("jobs.id", ondelete="CASCADE"), nullable=False)
    cron_expression: Mapped[str] = mapped_column(String(128), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    report_format: Mapped[ScheduledReportFormat] = mapped_column(
        _pg_str_enum(ScheduledReportFormat, "scheduledreportformat"),
        nullable=False,
        default=ScheduledReportFormat.PDF,
    )
    delivery_type: Mapped[ScheduledReportDelivery] = mapped_column(
        _pg_str_enum(ScheduledReportDelivery, "scheduledreportdelivery"),
        nullable=False,
    )
    config_json: Mapped[dict | None] = mapped_column(JSON)
    encrypted_secret: Mapped[str | None] = mapped_column(Text)
    last_delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_delivered_run_id: Mapped[int | None] = mapped_column(
        ForeignKey("job_runs.id", ondelete="SET NULL")
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    job: Mapped["Job"] = relationship()
    last_delivered_run: Mapped["JobRun | None"] = relationship(foreign_keys=[last_delivered_run_id])


class ScheduledReportDeliveryAttempt(Base):
    """Durable claim for scheduled report delivery (idempotency)."""

    __tablename__ = "scheduled_report_delivery_attempts"
    __table_args__ = (
        UniqueConstraint("schedule_id", "delivery_key", name="uq_scheduled_report_delivery_key"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    schedule_id: Mapped[int] = mapped_column(
        ForeignKey("scheduled_reports.id", ondelete="CASCADE"), nullable=False, index=True
    )
    delivery_key: Mapped[str] = mapped_column(String(256), nullable=False)
    job_run_id: Mapped[int] = mapped_column(ForeignKey("job_runs.id", ondelete="CASCADE"), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="claimed")
    error_message: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    schedule: Mapped["ScheduledReport"] = relationship()
    job_run: Mapped["JobRun"] = relationship()


class JobTemplate(Base):
    __tablename__ = "job_templates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    profile_id: Mapped[int | None] = mapped_column(ForeignKey("profiles.id", ondelete="SET NULL"))
    playbook_id: Mapped[int | None] = mapped_column(ForeignKey("playbooks.id", ondelete="SET NULL"))
    execution_type: Mapped[ExecutionType | None] = mapped_column(
        Enum(ExecutionType, name="executiontype", create_constraint=False, native_enum=True),
        nullable=True,
    )
    dynamic_filter: Mapped[dict | None] = mapped_column(JSON)
    cron_expression: Mapped[str | None] = mapped_column(String(128))
    is_scheduled: Mapped[bool] = mapped_column(Boolean, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    owner_sub: Mapped[str | None] = mapped_column(String(256), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    profile: Mapped["Profile | None"] = relationship()
    playbook: Mapped["Playbook | None"] = relationship()
    template_hosts: Mapped[list["JobTemplateHost"]] = relationship(
        back_populates="template", cascade="all, delete-orphan"
    )


class JobTemplateHost(Base):
    __tablename__ = "job_template_hosts"

    template_id: Mapped[int] = mapped_column(
        ForeignKey("job_templates.id", ondelete="CASCADE"), primary_key=True
    )
    host_id: Mapped[int] = mapped_column(ForeignKey("hosts.id", ondelete="CASCADE"), primary_key=True)

    template: Mapped["JobTemplate"] = relationship(back_populates="template_hosts")
    host: Mapped["Host"] = relationship()


class AuditFlowRun(Base):
    __tablename__ = "audit_flow_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    status: Mapped[AuditFlowStatus] = mapped_column(
        _pg_str_enum(AuditFlowStatus, "auditflowstatus"),
        default=AuditFlowStatus.PENDING,
        nullable=False,
    )
    targets_json: Mapped[list] = mapped_column(JSON, nullable=False, default=list)
    error_message: Mapped[str | None] = mapped_column(Text)
    owner_sub: Mapped[str | None] = mapped_column(String(256), index=True)
    hosts_found: Mapped[int] = mapped_column(Integer, default=0)
    save_to_inventory: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    credentials: Mapped[list["AuditFlowCredential"]] = relationship(
        back_populates="run", cascade="all, delete-orphan"
    )
    hosts: Mapped[list["AuditFlowHost"]] = relationship(
        back_populates="run",
        cascade="all, delete-orphan",
        order_by="AuditFlowHost.id",
    )


class AuditFlowCredential(Base):
    __tablename__ = "audit_flow_credentials"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("audit_flow_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    label: Mapped[str] = mapped_column(String(128), nullable=False)
    credential_type: Mapped[CredentialType] = mapped_column(
        Enum(CredentialType, name="credentialtype", create_constraint=False, native_enum=True),
        nullable=False,
    )
    username: Mapped[str] = mapped_column(String(128), nullable=False)
    encrypted_secret: Mapped[str] = mapped_column(Text, nullable=False)
    encrypted_key_passphrase: Mapped[str | None] = mapped_column(Text)
    service_username: Mapped[str | None] = mapped_column(String(128))
    encrypted_service_secret: Mapped[str | None] = mapped_column(Text)

    run: Mapped["AuditFlowRun"] = relationship(back_populates="credentials")


class AuditFlowHost(Base):
    __tablename__ = "audit_flow_hosts"
    __table_args__ = (UniqueConstraint("run_id", "ip_address", name="uq_audit_flow_host_ip"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("audit_flow_runs.id", ondelete="CASCADE"), nullable=False, index=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(256))
    platform: Mapped[str | None] = mapped_column(String(16))
    os_guess: Mapped[str | None] = mapped_column(String(256))
    open_ports: Mapped[str | None] = mapped_column(Text)
    nmap_services: Mapped[str | None] = mapped_column(Text)
    credential_id: Mapped[int | None] = mapped_column(
        ForeignKey("audit_flow_credentials.id", ondelete="SET NULL")
    )
    profile_id: Mapped[int | None] = mapped_column(ForeignKey("profiles.id", ondelete="SET NULL"))
    profile_name: Mapped[str | None] = mapped_column(String(256))
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    alternatives_json: Mapped[list | None] = mapped_column(JSON)
    extra_profiles_json: Mapped[list | None] = mapped_column(JSON)
    extra_runs_json: Mapped[list | None] = mapped_column(JSON)
    selected: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    skip_reason: Mapped[str | None] = mapped_column(String(64))
    skip_detail: Mapped[str | None] = mapped_column(Text)
    ssh_host_key_fingerprint: Mapped[str | None] = mapped_column(String(128))
    ssh_known_hosts_entry: Mapped[str | None] = mapped_column(Text)
    ephemeral_host_id: Mapped[int | None] = mapped_column(ForeignKey("hosts.id", ondelete="SET NULL"))
    ephemeral_credential_id: Mapped[int | None] = mapped_column(
        ForeignKey("credentials.id", ondelete="SET NULL")
    )
    job_run_id: Mapped[int | None] = mapped_column(ForeignKey("job_runs.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    run: Mapped["AuditFlowRun"] = relationship(back_populates="hosts")
    credential: Mapped["AuditFlowCredential | None"] = relationship()
    profile: Mapped["Profile | None"] = relationship()
