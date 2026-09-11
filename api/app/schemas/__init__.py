import json
from datetime import datetime
from typing import Annotated, Generic, Literal, TypeVar

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator, model_validator

from app.models import (
    CategoryType,
    CheckStatus,
    CredentialType,
    DeadLetterStatus,
    ExecutionType,
    JobScope,
    JobStatus,
    NetworkCheckMode,
    NetworkVendor,
    NotificationChannelType,
    NotificationEventType,
    ScriptKind,
    ScheduledReportDelivery,
    ScheduledReportFormat,
    UserRole,
    WaiverStatus,
)

from secaudit_core.cron import validate_cron_expression
from secaudit_core.sensitive_data import reject_secret_config

T = TypeVar("T")


def _strip_str(value: object) -> object:
    if isinstance(value, str):
        return value.strip()
    return value


StrippedStr = Annotated[str, BeforeValidator(_strip_str)]


class PaginatedResponse(BaseModel, Generic[T]):
    items: list[T]
    total: int
    offset: int
    limit: int


class AuditLogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    actor_username: str
    actor_roles: list[str] | None = None
    action: str
    resource_type: str
    resource_id: str | None = None
    resource_name: str | None = None
    outcome: Literal["success", "failed"]
    ip_address: str | None = None
    user_agent: str | None = None
    metadata_json: dict | None = None


class AuditMetricPoint(BaseModel):
    label: str
    count: int


class AuditTimelinePoint(BaseModel):
    day: str
    count: int


class AuditOverviewRead(BaseModel):
    total_events: int
    period_days: int
    events_over_time: list[AuditTimelinePoint]
    top_actions: list[AuditMetricPoint]
    top_actors: list[AuditMetricPoint]
    outcomes: list[AuditMetricPoint]
    resource_types: list[AuditMetricPoint]


SearchResultType = Literal["host", "job", "run", "profile", "remediation"]



class SearchResultItem(BaseModel):
    type: SearchResultType
    id: int
    title: str
    subtitle: str | None = None
    href: str
    score: int | None = None


class SearchResponse(BaseModel):
    items: list[SearchResultItem]
    query: str


class HealthResponse(BaseModel):
    status: str
    app_name: str
    version: str = "0.1.0"


class ComponentHealth(BaseModel):
    status: Literal["ok", "error"]
    detail: str | None = None


class ReadinessResponse(BaseModel):
    status: Literal["ok", "error"]
    app_name: str
    version: str = "0.1.0"
    components: dict[str, ComponentHealth]


# --- Categories ---


class CategoryBase(BaseModel):
    name: str
    slug: str
    category_type: CategoryType
    description: str | None = None
    parent_id: int | None = None


class CategoryCreate(CategoryBase):
    pass


class CategoryRead(CategoryBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime


# --- Profiles ---


class ProfileBase(BaseModel):
    profile_name: str
    version: str = "1.0"
    summary: str | None = None
    category_id: int | None = None
    package_path: str | None = None
    source_format: str = "custom"
    profile_family: str | None = None
    scap_profile_id: str | None = None
    profile_title: str | None = None
    benchmark_ref: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    os_vendor: str | None = None
    is_active: bool = True


class ProfileCreate(ProfileBase):
    pass


class ProfileRead(ProfileBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    category_name: str | None = None
    package_version: str | None = None
    needs_update: bool = False


class InterpreterRuleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    regex: str
    extraction_type: str
    tech_name: str


class CheckScriptRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    execution_type: ExecutionType
    script_file: str
    script_kind: ScriptKind = ScriptKind.AUDIT
    description: str | None
    interpreter_rules: list[InterpreterRuleRead] = []


class CheckScriptContentRead(BaseModel):
    script_file: str
    content: str


class CheckScriptContentUpdate(BaseModel):
    content: str


class ProfileRuleRead(BaseModel):
    num: str | None = None
    tech_name: str
    requirement_id: str
    title: str | None = None
    explanation: str | None = None
    impact: str | None = None
    scope: str | None = None
    check_script: str | None = None
    scap_rule_id: str | None = None
    criticality: str | None = None


class ProfileRuleUpdate(BaseModel):
    title: str | None = None
    explanation: str | None = None
    impact: str | None = None
    scope: str | None = None


class ProfileRuleChangelogEntry(BaseModel):
    id: str
    at: str
    actor: str | None = None
    requirement_id: str
    profile_version_before: str | None = None
    profile_version_after: str | None = None
    changes: dict[str, dict[str, str | None]] = {}


class ProfileRuleUpdateResult(BaseModel):
    rule: ProfileRuleRead
    profile_version: str
    changelog_entry: ProfileRuleChangelogEntry


class ProfileDetail(ProfileRead):
    check_scripts: list[CheckScriptRead] = []
    remediation_scripts: list[CheckScriptRead] = []


class ProfilesCatalogEntry(BaseModel):
    package_path: str
    profile_name: str
    version: str
    summary: str | None = None
    profile_family: str
    category_slug: str
    benchmark_ref: str | None = None
    platform: str
    os_name: str | None = None
    os_version: str | None = None
    os_vendor: str | None = None
    imported: bool
    profile_id: int | None = None
    imported_version: str | None = None
    is_latest: bool = False
    update_available: bool = False


class ProfilesCatalogSyncStatus(BaseModel):
    enabled: bool
    interval_seconds: int
    update_existing: bool
    mount_path: str
    mount_available: bool
    pending_imports: int
    pending_updates: int
    last_run_at: datetime | None = None
    last_run_skipped: bool = False
    last_run_skip_reason: str | None = None
    last_imported_count: int = 0
    last_updated_count: int = 0
    last_skipped_count: int = 0
    last_error_count: int = 0


class ProfilesBulkImportRequest(BaseModel):
    package_paths: list[str]
    skip_existing: bool = True
    update_existing: bool = False


class ProfilesBulkImportError(BaseModel):
    package_path: str
    message: str


class ProfilesBulkImportResult(BaseModel):
    imported: list[ProfileRead]
    skipped: list[str]
    errors: list[ProfilesBulkImportError]


class ProfileDependencies(BaseModel):
    jobs: int = 0
    remediation_jobs: int = 0
    waivers: int = 0
    job_runs: int = 0
    check_results: int = 0
    remediation_runs: int = 0
    active_runs: int = 0

    @property
    def has_blocking(self) -> bool:
        return self.jobs > 0 or self.remediation_jobs > 0 or self.waivers > 0


class ProfilesBulkActionRequest(BaseModel):
    profile_ids: list[int]
    cascade: bool = False


class ProfilesBulkActionError(BaseModel):
    profile_id: int
    message: str
    code: str | None = None
    dependencies: ProfileDependencies | None = None


class ProfilesBulkActionResult(BaseModel):
    succeeded: list[int]
    failed: list[ProfilesBulkActionError]


class ProfileSyncResult(BaseModel):
    profile: ProfileRead
    updated: bool


class ScapProfilePreview(BaseModel):
    profile_id: str
    title: str
    description: str = ""
    benchmark_title: str
    profile_family: str


# --- Hosts ---


class HostBase(BaseModel):
    name: StrippedStr
    hostname: StrippedStr
    port: int = 22
    os_type: str | None = None
    credential_id: int | None = None
    is_active: bool = True


class HostLinkedCredentialRead(BaseModel):
    id: int
    name: str
    credential_type: CredentialType
    username: str | None = None


class HostCreate(HostBase):
    credential_ids: list[int] = Field(default_factory=list)


class HostUpdate(BaseModel):
    name: StrippedStr | None = None
    hostname: StrippedStr | None = None
    port: int | None = None
    os_type: str | None = None
    credential_id: int | None = None
    credential_ids: list[int] | None = None
    is_active: bool | None = None
    ssh_host_key_fingerprint: str | None = None
    clear_ssh_host_key: bool = False


class HostCredentialLinkRequest(BaseModel):
    credential_id: int


class HostRead(HostBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    tags: list[str] = Field(default_factory=list)
    owner_sub: str | None = None
    ssh_host_key_fingerprint: str | None = None
    credential_ids: list[int] = Field(default_factory=list)
    linked_credentials: list[HostLinkedCredentialRead] = Field(default_factory=list)


class HostSshFingerprintScanResponse(BaseModel):
    fingerprint: str
    saved: bool


class HostTagRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    created_at: datetime


class HostTagAssignRequest(BaseModel):
    tag_names: list[StrippedStr] = Field(default_factory=list)


class DynamicHostFilter(BaseModel):
    tags: list[StrippedStr] = Field(default_factory=list)
    active_only: bool = True
    search: str | None = None
    os_type: str | None = None


class HostBulkDeleteRequest(BaseModel):
    host_ids: list[int] = Field(..., min_length=1)


class HostBulkDeleteConflict(BaseModel):
    host_id: int
    detail: str


class HostBulkDeleteResponse(BaseModel):
    deleted: list[int]
    conflicts: list[HostBulkDeleteConflict]


# --- Inventory scans ---


def _coerce_open_ports(value: object) -> list[int]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        import json

        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            return []
        return parsed if isinstance(parsed, list) else []
    return []


class InventoryScanCreate(BaseModel):
    target: str = Field(..., min_length=1, max_length=256, description="CIDR, IP, or IP range for nmap")
    nmap_flags: str | None = Field(
        None,
        max_length=256,
        description="Optional custom nmap flags (empty = default two-phase scan)",
    )


class InventoryScanResultRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ip_address: str
    resolved_hostname: str | None
    host_id: int | None
    open_ports: Annotated[list[int], BeforeValidator(_coerce_open_ports)] = []
    ports_scanned: bool = True
    is_active: bool = False
    created_at: datetime

    @model_validator(mode="before")
    @classmethod
    def _derive_ports_scanned(cls, data: object) -> object:
        """None open_ports means port scan not finished yet for this host."""
        if hasattr(data, "open_ports"):
            raw = getattr(data, "open_ports")
            return {
                "id": data.id,
                "ip_address": data.ip_address,
                "resolved_hostname": data.resolved_hostname,
                "host_id": data.host_id,
                "open_ports": raw,
                "ports_scanned": raw is not None,
                "is_active": data.is_active,
                "created_at": data.created_at,
            }
        if isinstance(data, dict) and "ports_scanned" not in data:
            return {**data, "ports_scanned": data.get("open_ports") is not None}
        return data


class InventoryScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target: str
    status: JobStatus
    started_at: datetime | None
    finished_at: datetime | None
    error_message: str | None
    hosts_found: int
    hosts_created: int
    nmap_flags: str | None = None
    owner_sub: str | None = None
    created_at: datetime


class InventoryScanDetail(InventoryScanRead):
    results: list[InventoryScanResultRead] = []


# --- Credentials ---


class CredentialBase(BaseModel):
    name: str
    credential_type: CredentialType
    username: str | None = None
    service_username: str | None = None
    description: str | None = None


class CredentialCreate(CredentialBase):
    secret: str = Field(..., min_length=1, description="Password, private key, or token")
    key_passphrase: str | None = Field(
        default=None,
        description="Passphrase for encrypted SSH private keys",
    )
    service_secret: str | None = Field(
        default=None,
        description="Password or token for the target service (database, middleware, etc.)",
    )


class CredentialUpdate(BaseModel):
    name: str | None = None
    credential_type: CredentialType | None = None
    username: str | None = None
    secret: str | None = None
    key_passphrase: str | None = None
    service_username: str | None = None
    service_secret: str | None = None
    description: str | None = None


class CredentialRead(CredentialBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    has_service_secret: bool = False
    created_at: datetime


# --- Notifications ---


class NotificationChannelBase(BaseModel):
    name: str
    channel_type: NotificationChannelType
    is_active: bool = True
    events: list[str] = Field(default_factory=list)
    config_json: dict | None = None

    _reject_config_secrets = field_validator("config_json", mode="before")(
        reject_secret_config
    )


class NotificationChannelCreate(NotificationChannelBase):
    secret: str | None = Field(default=None, description="Webhook URL, SMTP password, or API token")

    @field_validator("events", mode="before")
    @classmethod
    def _normalize_events(cls, value: object) -> list[str]:
        if not value:
            return []
        normalized: list[str] = []
        for item in value:
            normalized.append(item.value if hasattr(item, "value") else str(item))
        return normalized


class NotificationChannelUpdate(BaseModel):
    name: str | None = None
    channel_type: NotificationChannelType | None = None
    is_active: bool | None = None
    events: list[str] | None = None
    config_json: dict | None = None
    secret: str | None = None

    _reject_config_secrets = field_validator("config_json", mode="before")(
        reject_secret_config
    )


class NotificationChannelRead(NotificationChannelBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    owner_sub: str | None = None
    has_secret: bool = False
    created_at: datetime
    updated_at: datetime


class NotificationTestResponse(BaseModel):
    sent: int
    skipped: int
    errors: list[str]


# --- Scheduled reports ---


class ScheduledReportBase(BaseModel):
    name: str
    job_id: int
    cron_expression: str
    is_active: bool = True
    report_format: ScheduledReportFormat = ScheduledReportFormat.PDF
    delivery_type: ScheduledReportDelivery
    config_json: dict | None = None

    _reject_config_secrets = field_validator("config_json", mode="before")(
        reject_secret_config
    )

    @field_validator("cron_expression")
    @classmethod
    def validate_cron(cls, value: str) -> str:
        validated = validate_cron_expression(value)
        if not validated:
            raise ValueError("Cron expression is required")
        return validated


class ScheduledReportCreate(ScheduledReportBase):
    secret: str | None = Field(
        default=None,
        description="SMTP password or S3 secret key override",
    )


class ScheduledReportUpdate(BaseModel):
    name: str | None = None
    job_id: int | None = None
    cron_expression: str | None = None
    is_active: bool | None = None
    report_format: ScheduledReportFormat | None = None
    delivery_type: ScheduledReportDelivery | None = None
    config_json: dict | None = None
    secret: str | None = None

    _reject_config_secrets = field_validator("config_json", mode="before")(
        reject_secret_config
    )

    @field_validator("cron_expression")
    @classmethod
    def validate_cron(cls, value: str | None) -> str | None:
        return validate_cron_expression(value)


class ScheduledReportRead(ScheduledReportBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    has_secret: bool = False
    last_delivered_at: datetime | None = None
    last_delivered_run_id: int | None = None
    created_at: datetime
    updated_at: datetime


class ScheduledReportDeliverResponse(BaseModel):
    delivered: bool
    reason: str | None = None
    run_id: int | None = None
    delivery_type: str | None = None
    attachments: list[str] = Field(default_factory=list)
    locations: list[str] = Field(default_factory=list)
    delivered_at: str | None = None


# --- Jobs ---


class JobBase(BaseModel):
    name: str
    profile_id: int | None = None
    playbook_id: int | None = None
    execution_type: ExecutionType | None = None
    dynamic_filter: DynamicHostFilter | None = None
    cron_expression: str | None = None
    is_scheduled: bool = False
    is_active: bool = True
    scope: JobScope = JobScope.STANDARD
    network_check_mode: NetworkCheckMode | None = None
    webhook_enabled: bool = False
    webhook_events: list[NotificationEventType] = Field(
        default_factory=lambda: [NotificationEventType.RUN_COMPLETED, NotificationEventType.RUN_FAILED]
    )


class JobCreate(JobBase):
    host_ids: list[int] = Field(default_factory=list)
    webhook_url: str | None = None

    @field_validator("cron_expression")
    @classmethod
    def validate_cron(cls, value: str | None) -> str | None:
        return validate_cron_expression(value)

    @model_validator(mode="after")
    def require_hosts_or_group(self) -> "JobCreate":
        if not self.host_ids and self.dynamic_filter is None:
            raise ValueError("host_ids or dynamic_filter is required")
        return self


class JobUpdate(BaseModel):
    name: str | None = None
    profile_id: int | None = None
    playbook_id: int | None = None
    execution_type: ExecutionType | None = None
    dynamic_filter: DynamicHostFilter | None = None
    cron_expression: str | None = None
    is_scheduled: bool | None = None
    is_active: bool | None = None
    scope: JobScope | None = None
    network_check_mode: NetworkCheckMode | None = None
    host_ids: list[int] | None = Field(default=None, min_length=1)
    webhook_enabled: bool | None = None
    webhook_events: list[NotificationEventType] | None = None
    webhook_url: str | None = None
    clear_webhook_url: bool | None = None

    @field_validator("cron_expression")
    @classmethod
    def validate_cron(cls, value: str | None) -> str | None:
        return validate_cron_expression(value)


class JobRead(JobBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    host_ids: list[int] = Field(default_factory=list)
    owner_sub: str | None = None
    has_webhook_url: bool = False


class JobTemplateBase(BaseModel):
    name: str
    description: str | None = None
    profile_id: int | None = None
    playbook_id: int | None = None
    execution_type: ExecutionType | None = None
    dynamic_filter: DynamicHostFilter | None = None
    cron_expression: str | None = None
    is_scheduled: bool = False
    is_active: bool = True

    @field_validator("cron_expression")
    @classmethod
    def validate_cron(cls, value: str | None) -> str | None:
        return validate_cron_expression(value)

    @model_validator(mode="after")
    def require_profile_or_playbook(self) -> "JobTemplateBase":
        if not self.profile_id and not self.playbook_id:
            raise ValueError("profile_id or playbook_id is required")
        return self


class JobTemplateCreate(JobTemplateBase):
    host_ids: list[int] = Field(default_factory=list)


class JobTemplateUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    profile_id: int | None = None
    playbook_id: int | None = None
    execution_type: ExecutionType | None = None
    dynamic_filter: DynamicHostFilter | None = None
    cron_expression: str | None = None
    is_scheduled: bool | None = None
    is_active: bool | None = None
    host_ids: list[int] | None = None

    @field_validator("cron_expression")
    @classmethod
    def validate_cron(cls, value: str | None) -> str | None:
        return validate_cron_expression(value)


class JobTemplateRead(JobTemplateBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: datetime
    host_ids: list[int] = Field(default_factory=list)
    profile_name: str | None = None
    playbook_name: str | None = None
    owner_sub: str | None = None


class JobTemplateApply(BaseModel):
    name: str | None = None
    host_ids: list[int] | None = None
    dynamic_filter: DynamicHostFilter | None = None
    run_after_create: bool = False


class JobRunLogEntry(BaseModel):
    job_run_id: int
    level: str
    message: str
    timestamp: str


# --- Playbooks ---


class PlaybookBase(BaseModel):
    name: str
    description: str | None = None
    content: str
    is_active: bool = True
    scope: JobScope = JobScope.STANDARD
    platform: Literal["linux", "windows", "network"] = "linux"
    kind: Literal["user", "compliance_template"] = "user"
    version: str = "1.0"
    profile_id: int | None = None


class PlaybookCreate(BaseModel):
    name: str
    description: str | None = None
    content: str
    is_active: bool = True
    scope: JobScope = JobScope.STANDARD
    platform: Literal["linux", "windows", "network"] = "linux"


class PlaybookUpdate(BaseModel):
    name: str | None = None
    description: str | None = None
    content: str | None = None
    is_active: bool | None = None
    platform: Literal["linux", "windows", "network"] | None = None


class PlaybookContentUpdate(BaseModel):
    content: str = Field(min_length=1)


class PlaybookChangelogEntry(BaseModel):
    id: str
    at: str
    actor: str | None = None
    playbook_version_before: str | None = None
    playbook_version_after: str | None = None
    changes: dict[str, dict[str, str | None]] = {}


class PlaybookRead(PlaybookBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    owner_sub: str | None = None
    profile_name: str | None = None
    created_at: datetime
    updated_at: datetime


class PlaybookContentUpdateResult(BaseModel):
    playbook: PlaybookRead
    playbook_version: str
    changelog_entry: PlaybookChangelogEntry


class PlaybookValidateResponse(BaseModel):
    valid: bool
    message: str


class PlaybookTemplateRead(BaseModel):
    id: str
    name: str
    description: str
    category: str
    scope: JobScope = JobScope.STANDARD
    content: str
    content_fast: str | None = None


class PlaybookRunRequest(BaseModel):
    host_ids: list[int] = Field(min_length=1)
    connection_mode: Literal["auto", "ssh", "paramiko", "winrm"] = "auto"


class PlaybookRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    job_id: int
    playbook_id: int | None = None
    playbook_name: str | None = None
    status: JobStatus
    started_at: datetime | None
    finished_at: datetime | None
    error_message: str | None
    created_at: datetime
    host_count: int = 0
    host_ids: list[int] = Field(default_factory=list)


class JobRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    job_id: int
    status: JobStatus
    started_at: datetime | None
    finished_at: datetime | None
    celery_task_id: str | None
    error_message: str | None
    created_at: datetime


class CheckResultRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    host_id: int
    host_name: str | None = None
    rule_tech_name: str
    status: CheckStatus
    message: str | None
    raw_output: str | None = None
    created_at: datetime
    is_waived: bool = False
    waiver_id: int | None = None


class JobRunDetail(JobRunRead):
    check_results: list[CheckResultRead] = []


# --- Remediation ---


class RemediationJobBase(BaseModel):
    name: str
    profile_id: int
    remediation_script_id: int | None = None
    dynamic_filter: DynamicHostFilter | None = None
    execution_type: ExecutionType
    scope: JobScope = JobScope.STANDARD
    cron_expression: str | None = None
    is_scheduled: bool = False
    is_active: bool = True
    webhook_enabled: bool = False
    webhook_events: list[NotificationEventType] = Field(
        default_factory=lambda: [NotificationEventType.RUN_COMPLETED, NotificationEventType.RUN_FAILED]
    )


class RemediationJobCreate(RemediationJobBase):
    host_ids: list[int] = Field(default_factory=list)
    webhook_url: str | None = None

    @field_validator("cron_expression")
    @classmethod
    def validate_cron(cls, value: str | None) -> str | None:
        return validate_cron_expression(value)

    @model_validator(mode="after")
    def require_targets(self) -> "RemediationJobCreate":
        if not self.host_ids and self.dynamic_filter is None:
            raise ValueError("host_ids or dynamic_filter is required")
        return self


class RemediationJobUpdate(BaseModel):
    name: str | None = None
    profile_id: int | None = None
    remediation_script_id: int | None = None
    dynamic_filter: DynamicHostFilter | None = None
    execution_type: ExecutionType | None = None
    scope: JobScope | None = None
    cron_expression: str | None = None
    is_scheduled: bool | None = None
    is_active: bool | None = None
    host_ids: list[int] | None = Field(default=None, min_length=1)
    webhook_enabled: bool | None = None
    webhook_events: list[NotificationEventType] | None = None
    webhook_url: str | None = None
    clear_webhook_url: bool | None = None

    @field_validator("cron_expression")
    @classmethod
    def validate_cron(cls, value: str | None) -> str | None:
        return validate_cron_expression(value)


class RemediationJobRead(RemediationJobBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    host_ids: list[int] = Field(default_factory=list)
    owner_sub: str | None = None
    has_webhook_url: bool = False


class RemediationRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    remediation_job_id: int
    status: JobStatus
    started_at: datetime | None
    finished_at: datetime | None
    error_message: str | None
    created_at: datetime


class RemediationResultRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    remediation_run_id: int
    host_id: int
    script_name: str
    status: CheckStatus
    message: str | None
    raw_output: str | None
    created_at: datetime


class RemediationRunDetail(RemediationRunRead):
    results: list[RemediationResultRead] = []


class RemediationRunLogEntry(BaseModel):
    remediation_run_id: int
    level: str
    message: str
    timestamp: str


class FailedCheckSummary(BaseModel):
    host_id: int
    rule_tech_name: str
    status: CheckStatus
    message: str | None = None


class RemediationScriptOption(BaseModel):
    id: int
    name: str
    execution_type: ExecutionType


class RemediationSuggestion(BaseModel):
    source_run_id: int
    source_job_id: int
    source_job_name: str
    profile_id: int
    profile_name: str
    host_ids: list[int]
    failed_count: int
    failed_checks: list[FailedCheckSummary]
    remediation_scripts: list[RemediationScriptOption]
    suggested_name: str
    default_execution_type: ExecutionType
    default_remediation_script_id: int | None = None


class RemediationFromRunRequest(BaseModel):
    source_run_id: int
    name: str | None = None
    remediation_script_id: int | None = None
    run_remediation: bool = True
    set_baseline: bool = True


class RemediationFromRunResponse(BaseModel):
    remediation_job_id: int
    remediation_run_id: int | None = None
    baseline_run_id: int | None = None
    source_run_id: int
    source_job_id: int


# --- Users ---


class UserBase(BaseModel):
    username: str
    email: str
    full_name: str | None = None
    role: UserRole = UserRole.OPERATOR


class UserCreate(UserBase):
    password: str = Field(..., min_length=8)


class UserUpdate(BaseModel):
    username: str | None = None
    email: str | None = None
    full_name: str | None = None
    role: UserRole | None = None
    is_active: bool | None = None
    password: str | None = Field(default=None, min_length=8)


class UserRead(UserBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    is_active: bool
    created_at: datetime


# --- Reports ---


class ReportSummary(BaseModel):
    job_run_id: int
    total_checks: int
    passed: int
    failed: int
    skipped: int
    errors: int
    waived: int = 0
    compliance_percent: float
    compliance_percent_raw: float | None = None


class ComplianceWaiverBase(BaseModel):
    profile_id: int
    rule_tech_name: str
    host_id: int | None = None
    job_id: int | None = None
    reason: str
    expires_at: datetime | None = None


class ComplianceWaiverCreate(ComplianceWaiverBase):
    auto_approve: bool = False


class ComplianceWaiverUpdate(BaseModel):
    reason: str | None = None
    expires_at: datetime | None = None


class ComplianceWaiverReject(BaseModel):
    reason: str | None = None


class ComplianceWaiverRead(ComplianceWaiverBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    status: WaiverStatus
    requested_by: str
    approved_by: str | None = None
    approved_at: datetime | None = None
    rejected_by: str | None = None
    rejected_at: datetime | None = None
    rejection_reason: str | None = None
    is_active: bool
    owner_sub: str | None = None
    created_at: datetime
    updated_at: datetime


class DriftItem(BaseModel):
    host_id: int
    rule_tech_name: str
    baseline_status: CheckStatus | None
    current_status: CheckStatus | None
    baseline_message: str | None = None
    current_message: str | None = None
    change: Literal["improved", "regressed", "unchanged", "new", "removed"]


class DriftSummary(BaseModel):
    current_run_id: int
    baseline_run_id: int
    improved: int
    regressed: int
    unchanged: int
    new: int
    removed: int
    baseline_compliance_percent: float
    current_compliance_percent: float
    compliance_delta: float


class DriftReport(BaseModel):
    summary: DriftSummary
    items: list[DriftItem]


class DiffRow(BaseModel):
    """Paired check row for side-by-side Diff (left = run A, right = run B)."""

    key: str
    host_id: int
    rule_tech_name: str
    left_status: CheckStatus | None
    right_status: CheckStatus | None
    left_message: str | None = None
    right_message: str | None = None
    change: Literal["improved", "regressed", "unchanged", "new", "removed"]


class DiffSummary(BaseModel):
    left_run_id: int
    right_run_id: int
    improved: int
    regressed: int
    unchanged: int
    new: int
    removed: int
    left_compliance_percent: float
    right_compliance_percent: float
    compliance_delta: float


class DiffReport(BaseModel):
    summary: DiffSummary
    items: list[DiffRow]


class MultiRunCompareRunSummary(BaseModel):
    run_id: int
    job_id: int
    status: JobStatus
    finished_at: datetime | None = None
    compliance_percent: float
    total_checks: int
    passed: int
    failed: int
    skipped: int
    errors: int


class MultiRunCompareCell(BaseModel):
    run_id: int
    status: CheckStatus | None = None
    message: str | None = None


class MultiRunCompareRow(BaseModel):
    host_id: int
    rule_tech_name: str
    severity: str | None = None
    cells: list[MultiRunCompareCell]


class MultiRunCompareReport(BaseModel):
    job_id: int
    run_ids: list[int]
    runs: list[MultiRunCompareRunSummary]
    rows: list[MultiRunCompareRow]


class JobBaselineRead(BaseModel):
    baseline_run_id: int | None


class JobBaselineSet(BaseModel):
    run_id: int


class DeadLetterRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    celery_task_id: str | None = None
    task_name: str
    queue: str
    args_json: str
    kwargs_json: str | None = None
    exception_type: str | None = None
    exception_message: str | None = None
    traceback_text: str | None = None
    retry_count: int
    status: DeadLetterStatus
    replay_task_id: str | None = None
    created_at: datetime
    replayed_at: datetime | None = None
    discarded_at: datetime | None = None


# --- Network operations ---


class NetworkDeviceConfigRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    job_id: int
    host_id: int | None = None
    vendor: NetworkVendor
    filename: str
    created_at: datetime


class NetworkRemediationConfigRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    remediation_run_id: int
    host_id: int | None = None
    vendor: NetworkVendor
    filename: str
    created_at: datetime


class NetworkRemediationConfigGenerate(BaseModel):
    vendor: NetworkVendor
    host_id: int | None = None
    hostname: str | None = None
    commands: list[str] = Field(default_factory=list)
    content: str = ""
    filename: str | None = None


# --- Trends ---


class ComplianceTimelinePoint(BaseModel):
    run_id: int
    job_id: int
    job_name: str
    finished_at: datetime
    compliance_percent: float
    passed: int
    failed: int
    total_checks: int


class HostCompliancePoint(BaseModel):
    host_id: int
    host_name: str
    compliance_percent: float
    passed: int
    failed: int
    total_checks: int


class ProfileCompliancePoint(BaseModel):
    profile_id: int
    profile_name: str
    job_count: int
    avg_compliance_percent: float
    latest_run_id: int | None


class StatusCountPoint(BaseModel):
    key: str
    count: int


class DailyOpsPoint(BaseModel):
    day: str
    runs: int
    passed: int
    failed: int
    avg_compliance_percent: float


class PlatformOpsPoint(BaseModel):
    platform: str
    hosts: int
    checks: int
    avg_compliance_percent: float


class JobOpsPoint(BaseModel):
    job_id: int
    job_name: str
    runs: int
    avg_compliance_percent: float
    passed: int
    failed: int
    latest_run_id: int | None = None


class RuleFailPoint(BaseModel):
    rule_tech_name: str
    fail_count: int


class ComplianceBandPoint(BaseModel):
    band: str
    count: int


class WeekdayHeatCell(BaseModel):
    weekday: int
    week_index: int
    week_start: str | None = None
    day: str | None = None
    avg_compliance_percent: float | None
    runs: int


class ComplianceOpsKpis(BaseModel):
    avg_compliance_percent: float | None = None
    prev_avg_compliance_percent: float | None = None
    completed_runs: int = 0
    failed_runs: int = 0
    running_runs: int = 0
    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    errors: int = 0
    hosts: int = 0
    profiles: int = 0
    jobs: int = 0
    waivers_approved: int = 0
    waivers_pending: int = 0


class ComplianceOpsOverview(BaseModel):
    days: int
    kpis: ComplianceOpsKpis
    outcome_mix: list[StatusCountPoint] = Field(default_factory=list)
    run_status_mix: list[StatusCountPoint] = Field(default_factory=list)
    bands: list[ComplianceBandPoint] = Field(default_factory=list)
    daily: list[DailyOpsPoint] = Field(default_factory=list)
    by_platform: list[PlatformOpsPoint] = Field(default_factory=list)
    by_job: list[JobOpsPoint] = Field(default_factory=list)
    top_failing_rules: list[RuleFailPoint] = Field(default_factory=list)
    heatmap: list[WeekdayHeatCell] = Field(default_factory=list)


class AuditFlowCredentialIn(BaseModel):
    label: str | None = None
    credential_type: CredentialType
    username: StrippedStr
    secret: str = Field(..., min_length=1)
    key_passphrase: str | None = None
    service_username: StrippedStr | None = None
    service_secret: str | None = None


class AuditFlowCredentialAdd(AuditFlowCredentialIn):
    host_id: int | None = None


class AuditFlowCreate(BaseModel):
    targets: list[StrippedStr] = Field(..., min_length=1, max_length=16)
    credentials: list[AuditFlowCredentialIn] = Field(default_factory=list, max_length=20)
    save_to_inventory: bool = False


class AuditFlowCredentialRead(BaseModel):
    id: int
    label: str
    credential_type: CredentialType
    username: str
    service_username: str | None = None
    has_service_secret: bool = False


class AuditFlowExtraProfilePatch(BaseModel):
    profile_id: int
    selected: bool


class AuditFlowHostPatch(BaseModel):
    id: int
    selected: bool | None = None
    profile_id: int | None = None
    credential_id: int | None = None
    extra_profiles: list[AuditFlowExtraProfilePatch] | None = None


class AuditFlowHostsPatch(BaseModel):
    hosts: list[AuditFlowHostPatch] = Field(..., min_length=1)


class AuditFlowCheckSummary(BaseModel):
    job_run_id: int | None = None
    job_status: str | None = None
    error_message: str | None = None
    total_checks: int = 0
    passed: int = 0
    failed: int = 0
    skipped: int = 0
    errors: int = 0
    waived: int = 0
    compliance_percent: float = 0
    compliance_percent_raw: float | None = None
    profile_id: int | None = None
    profile_name: str | None = None


class AuditFlowHostRead(BaseModel):
    id: int
    ip_address: str
    hostname: str | None = None
    platform: str | None = None
    os_guess: str | None = None
    open_ports: list[int] = Field(default_factory=list)
    credential_id: int | None = None
    credential_label: str | None = None
    profile_id: int | None = None
    profile_name: str | None = None
    confidence: int = 0
    alternatives: list[dict] = Field(default_factory=list)
    extra_profiles: list[dict] = Field(default_factory=list)
    extra_checks: list[dict] = Field(default_factory=list)
    check_summary: dict | None = None
    selected: bool = False
    skip_reason: str | None = None
    skip_detail: str | None = None
    job_run_id: int | None = None
    ephemeral_host_id: int | None = None
    inventory_reused: bool = False
    ssh_host_key_fingerprint: str | None = None


class AuditFlowProgress(BaseModel):
    phase: str | None = None
    target: str | None = None
    address: str | None = None


class AuditFlowRunRead(BaseModel):
    id: int
    status: str
    targets: list[str] = Field(default_factory=list)
    error_message: str | None = None
    hosts_found: int = 0
    save_to_inventory: bool = False
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime
    hosts: list[AuditFlowHostRead] = Field(default_factory=list)
    credentials: list[AuditFlowCredentialRead] = Field(default_factory=list)
    progress: AuditFlowProgress | None = None


class AuditFlowLogEntry(BaseModel):
    audit_flow_run_id: int
    level: str
    message: str
    timestamp: str

