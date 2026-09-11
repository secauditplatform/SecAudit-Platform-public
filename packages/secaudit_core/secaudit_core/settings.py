from pydantic_settings import BaseSettings, SettingsConfigDict


class SecAuditSettings(BaseSettings):
    """Base settings shared by API and workers."""

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_env: str = "development"
    app_version: str = "1.0.0"
    secret_key: str = "dev-secret-key"

    # Data-at-rest encryption backend: fernet (dev), vault (Transit), aws_kms (BYO-KMS).
    secrets_backend: str = "fernet"
    secrets_fernet_allowed_in_production: bool = False
    vault_addr: str | None = None
    vault_token: str | None = None
    vault_token_file: str | None = None
    vault_transit_mount: str = "transit"
    vault_transit_key: str = "secaudit"
    aws_kms_key_id: str | None = None
    aws_kms_region: str | None = None

    ssh_known_hosts_path: str | None = None
    ssh_strict_host_key_checking: bool | None = None
    winrm_server_cert_validation: str | None = None

    @property
    def ssh_strict_host_key_checking_effective(self) -> bool:
        if self.ssh_strict_host_key_checking is not None:
            return self.ssh_strict_host_key_checking
        return self.app_env == "production"

    @property
    def winrm_server_cert_validation_effective(self) -> str:
        if self.winrm_server_cert_validation is not None:
            return self.winrm_server_cert_validation
        return "validate" if self.app_env == "production" else "ignore"

    postgres_host: str = "localhost"
    postgres_port: int = 5432
    postgres_db: str = "secaudit"
    postgres_user: str = "secaudit"
    postgres_password: str = "secaudit_dev"

    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/0"
    celery_result_backend: str = "redis://localhost:6379/1"
    # Redis Sentinel HA (when REDIS_SENTINEL_HOSTS is set, app Redis + Celery use Sentinel)
    redis_sentinel_hosts: str | None = None
    redis_sentinel_master_name: str = "secaudit-master"
    redis_sentinel_password: str | None = None
    redis_password: str | None = None
    redis_db: int = 0
    redis_ssl: bool = False
    redis_ssl_cert_reqs: str = "required"

    celery_task_soft_time_limit: int = 3600
    celery_task_time_limit: int = 3900
    stale_run_timeout_seconds: int | None = None
    pending_orphan_timeout_seconds: int | None = None
    beat_lock_ttl_seconds: int = 55
    job_host_concurrency: int = 4
    job_log_ttl_seconds: int = 86400
    raw_output_max_chars: int = 16000

    profiles_path: str = "/profiles"
    profiles_storage_path: str = "/data/profiles"
    profiles_auto_seed: bool = False
    profiles_catalog_sync_enabled: bool = False
    profiles_catalog_sync_interval_seconds: int = 3600
    profiles_catalog_sync_update_existing: bool = True

    notifications_enabled: bool = True
    frontend_base_url: str = "http://localhost:5173"
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    smtp_use_tls: bool = True

    scheduled_reports_enabled: bool = True
    object_rbac_enabled: bool = True
    s3_endpoint_url: str | None = None
    s3_region: str = "us-east-1"
    s3_bucket: str | None = None
    s3_access_key: str | None = None
    s3_secret_key: str | None = None
    s3_prefix: str = "reports"

    @property
    def stale_run_timeout_effective(self) -> int:
        if self.stale_run_timeout_seconds is not None:
            return self.stale_run_timeout_seconds
        return self.celery_task_time_limit * 2

    @property
    def pending_orphan_timeout_effective(self) -> int:
        if self.pending_orphan_timeout_seconds is not None:
            return self.pending_orphan_timeout_seconds
        return min(600, max(120, self.celery_task_soft_time_limit // 4))

    worker_heartbeat_max_age_seconds: int = 120
    outbox_poll_batch_size: int = 50
    redis_socket_connect_timeout_seconds: float = 2.0
    redis_socket_timeout_seconds: float = 2.0

    # Observability endpoint protection (Bearer / X-Observability-Token)
    metrics_bearer_token: str | None = None
    readiness_bearer_token: str | None = None
    readiness_cache_seconds: float = 5.0
    readiness_redact_details: bool = True

    # OpenTelemetry — off by default; enable per-service via env
    otel_enabled: bool = False
    otel_service_name: str | None = None
    otel_service_namespace: str = "secaudit"
    otel_exporter_otlp_endpoint: str | None = None
    otel_exporter_otlp_protocol: str = "http/protobuf"
    otel_exporter_otlp_headers: str | None = None
    otel_resource_attributes: str | None = None
    otel_sampler_ratio: float = 1.0
    otel_console_export: bool = False
    otel_instrument_logging: bool = True

    @property
    def aws_kms_region_effective(self) -> str:
        return self.aws_kms_region or self.s3_region or "us-east-1"

    @property
    def secrets_backend_effective(self) -> str:
        return (self.secrets_backend or "fernet").strip().lower()

    @property
    def database_url_sync(self) -> str:
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def redis_sentinel_enabled(self) -> bool:
        return bool(self.redis_sentinel_hosts and self.redis_sentinel_hosts.strip())

    @property
    def parsed_sentinel_hosts(self) -> list[tuple[str, int]]:
        from secaudit_core.redis_config import parse_sentinel_hosts

        return parse_sentinel_hosts(self.redis_sentinel_hosts or "")

    @property
    def celery_broker_url_effective(self) -> str:
        from secaudit_core.redis_config import build_sentinel_url, parse_redis_db

        if not self.redis_sentinel_enabled:
            return self.celery_broker_url
        db = parse_redis_db(self.celery_broker_url, default=0)
        return build_sentinel_url(
            hosts=self.parsed_sentinel_hosts,
            db=db,
            password=self.redis_sentinel_password,
        )

    @property
    def celery_result_backend_effective(self) -> str:
        from secaudit_core.redis_config import build_sentinel_url, parse_redis_db

        if not self.redis_sentinel_enabled:
            return self.celery_result_backend
        db = parse_redis_db(self.celery_result_backend, default=1)
        return build_sentinel_url(
            hosts=self.parsed_sentinel_hosts,
            db=db,
            password=self.redis_sentinel_password,
        )

    def celery_transport_options(self) -> dict:
        from secaudit_core.redis_config import celery_transport_options

        if not self.redis_sentinel_enabled:
            return {}
        return celery_transport_options(
            master_name=self.redis_sentinel_master_name,
            sentinel_password=self.redis_sentinel_password,
        )
