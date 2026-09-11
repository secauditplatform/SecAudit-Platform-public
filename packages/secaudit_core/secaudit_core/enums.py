import enum


class CategoryType(str, enum.Enum):
    OS = "os"
    MIDDLEWARE = "middleware"
    NETWORK = "network"
    CONTAINER = "container"
    DATABASE = "database"
    WEB = "web"
    OTHER = "other"


class ExecutionType(str, enum.Enum):
    SSH = "ssh"
    WINRM = "winrm"
    ANSIBLE = "ansible"
    PYTHON = "python"


class ScriptKind(str, enum.Enum):
    AUDIT = "audit"
    REMEDIATION = "remediation"


class PlaybookKind(str, enum.Enum):
    USER = "user"
    COMPLIANCE_TEMPLATE = "compliance_template"


class CheckStatus(str, enum.Enum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"
    ERROR = "error"
    PENDING = "pending"


class WaiverStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    REVOKED = "revoked"


class JobStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class JobScope(str, enum.Enum):
    STANDARD = "standard"
    NETWORK = "network"


class NetworkCheckMode(str, enum.Enum):
    REMOTE = "remote"
    CONFIG_UPLOAD = "config_upload"
    BOTH = "both"


class NetworkVendor(str, enum.Enum):
    CISCO_IOS = "cisco_ios"
    CISCO_NXOS = "cisco_nxos"
    CISCO_ASA = "cisco_asa"
    JUNIPER_JUNOS = "juniper_junos"
    ARISTA_EOS = "arista_eos"
    HUAWEI = "huawei"
    H3C = "h3c"
    FORTINET = "fortinet"
    PALO_ALTO = "palo_alto"
    CHECK_POINT = "check_point"
    GENERIC = "generic"


class OutboxStatus(str, enum.Enum):
    PENDING = "pending"
    DISPATCHING = "dispatching"
    SENT = "sent"
    FAILED = "failed"
    CANCELLED = "cancelled"


class DeadLetterStatus(str, enum.Enum):
    PENDING = "pending"
    REPLAYED = "replayed"
    DISCARDED = "discarded"


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    OPERATOR = "operator"
    AUDITOR = "auditor"


class CredentialType(str, enum.Enum):
    SSH_PASSWORD = "ssh_password"
    SSH_KEY = "ssh_key"
    WINRM = "winrm"
    ANSIBLE_VAULT = "ansible_vault"


class NotificationChannelType(str, enum.Enum):
    EMAIL = "email"
    WEBHOOK = "webhook"
    SLACK = "slack"
    TEAMS = "teams"
    SIEM = "siem"


class NotificationEventType(str, enum.Enum):
    RUN_FAILED = "run_failed"
    RUN_COMPLETED = "run_completed"
    RUN_STALE = "run_stale"
    DISPATCH_FAILED = "dispatch_failed"
    WORKER_HEARTBEAT_STALE = "worker_heartbeat_stale"
    WORKER_HEARTBEAT_RECOVERED = "worker_heartbeat_recovered"
    AUDIT_EVENT = "audit_event"
    AUDIT_FAILED = "audit_failed"


class ScheduledReportFormat(str, enum.Enum):
    HTML = "html"
    PDF = "pdf"
    BOTH = "both"


class ScheduledReportDelivery(str, enum.Enum):
    EMAIL = "email"
    S3 = "s3"


class AuditFlowStatus(str, enum.Enum):
    PENDING = "pending"
    SCANNING = "scanning"
    READY = "ready"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
