from pathlib import Path

from secaudit_core.security import validate_bootstrap_admin_config
from secaudit_core.settings import SecAuditSettings


class Settings(SecAuditSettings):
    app_name: str = "SecAudit Platform"
    api_debug: bool = True

    cors_origins: str = "http://localhost:5173,http://localhost:3000"

    auth_enabled: bool = True
    # Public demo stand: block execute/mutate APIs (jobs, remediation, scans, …).
    demo_mode: bool = False
    # When true, username/password login authenticates against DB users
    # managed via the Users API/UI — there is no env-backed fallback account.
    local_auth_enabled: bool = False
    local_auth_token_ttl_seconds: int = 86400
    local_auth_refresh_token_ttl_seconds: int = 604800
    # Re-load active flag + roles from DB on every local JWT request (disable in unit tests).
    local_auth_revalidate_from_db: bool = True
    local_auth_rate_limit_enabled: bool = True
    local_auth_rate_limit_max_attempts: int = 10
    local_auth_rate_limit_window_seconds: int = 60
    # Comma-separated proxy peer IPs allowed to supply X-Forwarded-For for rate limits.
    trusted_proxy_ips: str = ""

    # Opt-in first local admin (created only when the users table is empty).
    bootstrap_admin_username: str | None = None
    bootstrap_admin_password: str | None = None
    bootstrap_admin_password_file: str | None = None
    bootstrap_admin_email: str | None = None

    console_enabled: bool = True
    console_allow_in_production: bool = False
    console_session_timeout_seconds: int = 3600
    console_command_timeout_seconds: int = 30
    console_command_output_max_bytes: int = 262144
    # When true and CONSOLE_SANDBOX_URL is set, API proxies WS to the sandbox
    # container and does not spawn console commands in the API process.
    console_sandbox_enabled: bool = False
    console_sandbox_url: str | None = None
    blocking_io_max_workers: int = 4
    blocking_io_timeout_seconds: int = 60
    metrics_scrape_timeout_seconds: float = 5.0
    # JWKS is fetched from keycloak_url (often an internal Docker hostname).
    keycloak_url: str = "http://localhost:8080"
    keycloak_realm: str = "secaudit"
    keycloak_client_id: str = "secaudit-frontend"
    keycloak_audience: str = "secaudit-api"
    keycloak_jwt_algorithms: str = "RS256"
    # Token iss claim uses the public URL browsers hit (e.g. localhost), not the internal JWKS host.
    keycloak_issuer: str | None = None

    @property
    def keycloak_issuer_url(self) -> str:
        if self.keycloak_issuer:
            return self.keycloak_issuer.rstrip("/")
        return f"{self.keycloak_url.rstrip('/')}/realms/{self.keycloak_realm}"

    @property
    def keycloak_jwks_url(self) -> str:
        return f"{self.keycloak_url.rstrip('/')}/realms/{self.keycloak_realm}/protocol/openid-connect/certs"

    @property
    def keycloak_jwt_algorithms_list(self) -> list[str]:
        return [item.strip() for item in self.keycloak_jwt_algorithms.split(",") if item.strip()]

    @property
    def database_url(self) -> str:
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def console_enabled_effective(self) -> bool:
        if not self.console_enabled:
            return False
        if self.app_env == "production" and not self.console_allow_in_production:
            return False
        return True

    @property
    def console_sandbox_enabled_effective(self) -> bool:
        """Sandbox proxy is used only when explicitly enabled and URL is configured."""
        if not self.console_sandbox_enabled:
            return False
        if not (self.console_sandbox_url or "").strip():
            return False
        return self.console_enabled_effective

    def get_bootstrap_admin_password(self) -> str | None:
        if not self.bootstrap_admin_password_file:
            return self.bootstrap_admin_password
        try:
            return Path(self.bootstrap_admin_password_file).read_text(encoding="utf-8").rstrip("\r\n")
        except OSError as exc:
            raise RuntimeError("Unable to read BOOTSTRAP_ADMIN_PASSWORD_FILE.") from exc

    def validate_bootstrap_admin_security(self) -> None:
        validate_bootstrap_admin_config(
            app_env=self.app_env,
            username=self.bootstrap_admin_username,
            password=self.get_bootstrap_admin_password(),
            password_from_secret_file=bool(self.bootstrap_admin_password_file),
            direct_password_configured=self.bootstrap_admin_password is not None,
            demo_mode=self.demo_mode,
        )


settings = Settings()
