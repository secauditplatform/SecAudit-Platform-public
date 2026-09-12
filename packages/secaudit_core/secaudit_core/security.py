DEFAULT_SECRET_KEY = "dev-secret-key"

# Documented / copy-paste secrets that must never pass production checks.
_SECRET_KEY_PLACEHOLDERS = {
    DEFAULT_SECRET_KEY,
    "change-me",
    "change-me-in-production",
    "change-me-in-production-use-openssl-rand-hex-32",
    "changeme",
    "secret",
    "secret-key",
}
_MIN_PRODUCTION_SECRET_KEY_LENGTH = 32
_MIN_PRODUCTION_SECRET_KEY_UNIQUE_CHARS = 10

# Weak / demo credentials that must never be used for bootstrap admin.
_BOOTSTRAP_PLACEHOLDER_USERNAMES = {
    "admin",
    "change-me",
    "changeme",
    "dev",
    "root",
    "user",
    "username",
}
_BOOTSTRAP_PLACEHOLDER_PASSWORDS = {
    "admin",
    "change-me",
    "change-me-in-production",
    "changeme",
    "dev",
    "password",
    "secaudit",
}
_MIN_PRODUCTION_BOOTSTRAP_PASSWORD_LENGTH = 16


def validate_production_secret_key(secret_key: str, app_env: str) -> None:
    """Refuse to start in production with a weak or documented SECRET_KEY."""
    if app_env.strip().lower() != "production":
        return

    raw = secret_key or ""
    normalized = raw.strip().lower()

    if not normalized or normalized == DEFAULT_SECRET_KEY:
        raise RuntimeError(
            "SECRET_KEY is still the default 'dev-secret-key'. "
            "Set a unique value in production (e.g. openssl rand -hex 32)."
        )

    if (
        normalized in _SECRET_KEY_PLACEHOLDERS
        or normalized.startswith(("<", "change-me", "changeme"))
    ):
        raise RuntimeError(
            "SECRET_KEY is a documented placeholder. "
            "Generate a unique value for production (e.g. openssl rand -hex 32)."
        )

    if len(raw) < _MIN_PRODUCTION_SECRET_KEY_LENGTH:
        raise RuntimeError(
            f"SECRET_KEY must be at least {_MIN_PRODUCTION_SECRET_KEY_LENGTH} characters "
            "in production (e.g. openssl rand -hex 32)."
        )

    if len(set(raw)) < _MIN_PRODUCTION_SECRET_KEY_UNIQUE_CHARS:
        raise RuntimeError(
            "SECRET_KEY does not have enough entropy for production. "
            "Generate a unique value (e.g. openssl rand -hex 32)."
        )


def validate_bootstrap_admin_config(
    *,
    app_env: str,
    username: str | None,
    password: str | None,
    password_from_secret_file: bool,
    direct_password_configured: bool,
    demo_mode: bool = False,
) -> None:
    """Reject insecure bootstrap-admin credentials.

    Bootstrap runs only when both username and password are configured.
    Weak demo values (including ``dev``/``dev``) are always rejected, except
    username ``admin`` when ``demo_mode`` is enabled for a locked-down public stand.
    Production additionally requires a secret-file password of sufficient length.
    """
    if not username and not password and not direct_password_configured and not password_from_secret_file:
        return
    if not username or not password:
        raise RuntimeError(
            "Bootstrap admin requires both BOOTSTRAP_ADMIN_USERNAME and a password "
            "(BOOTSTRAP_ADMIN_PASSWORD or BOOTSTRAP_ADMIN_PASSWORD_FILE)."
        )

    normalized_username = username.strip().lower()
    normalized_password = password.strip().lower()

    if len(normalized_username) < 3:
        raise RuntimeError("Bootstrap admin username is too short.")
    username_allowed_for_demo = demo_mode and normalized_username == "admin"
    if (
        not username_allowed_for_demo
        and (
            normalized_username in _BOOTSTRAP_PLACEHOLDER_USERNAMES
            or normalized_username.startswith(("<", "change-me", "changeme"))
        )
    ):
        raise RuntimeError("Bootstrap admin username is a known fallback or placeholder.")

    if normalized_password in _BOOTSTRAP_PLACEHOLDER_PASSWORDS or normalized_password.startswith(
        ("<", "change-me", "changeme")
    ):
        raise RuntimeError("Bootstrap admin password is a known fallback or placeholder.")

    if app_env.strip().lower() != "production":
        return

    if direct_password_configured or not password_from_secret_file:
        raise RuntimeError(
            "Production bootstrap admin requires BOOTSTRAP_ADMIN_PASSWORD_FILE backed by "
            "secret storage; BOOTSTRAP_ADMIN_PASSWORD must not be set."
        )

    if len(password) < _MIN_PRODUCTION_BOOTSTRAP_PASSWORD_LENGTH:
        raise RuntimeError(
            f"Production bootstrap admin password must contain at least "
            f"{_MIN_PRODUCTION_BOOTSTRAP_PASSWORD_LENGTH} characters."
        )


def validate_production_runtime_config(
    *,
    app_env: str,
    auth_enabled: bool,
    api_debug: bool,
    object_rbac_enabled: bool = True,
) -> None:
    """Refuse unsafe auth/debug settings in production."""
    if app_env.strip().lower() != "production":
        return

    if not auth_enabled:
        raise RuntimeError(
            "AUTH_ENABLED=false is forbidden in production (synthetic admin bypass)."
        )

    if api_debug:
        raise RuntimeError(
            "API_DEBUG=true is forbidden in production. Set API_DEBUG=false."
        )

    if not object_rbac_enabled:
        raise RuntimeError(
            "OBJECT_RBAC_ENABLED=false is forbidden in production "
            "(disables object ownership scoping)."
        )


def validate_production_secrets_backend(
    *,
    app_env: str,
    secrets_backend: str,
    secrets_fernet_allowed_in_production: bool,
    vault_addr: str | None,
    vault_token: str | None,
    vault_token_file: str | None,
    aws_kms_key_id: str | None,
) -> None:
    """Require external KMS/Vault for data-at-rest secrets in production."""
    if app_env.strip().lower() != "production":
        return

    backend = (secrets_backend or "fernet").strip().lower()
    if backend == "fernet" and not secrets_fernet_allowed_in_production:
        raise RuntimeError(
            "SECRETS_BACKEND=fernet is forbidden in production. "
            "Use SECRETS_BACKEND=vault or aws_kms, or set SECRETS_FERNET_ALLOWED_IN_PRODUCTION=true for migration only."
        )

    if backend == "vault":
        has_token = bool(vault_token and vault_token.strip()) or bool(vault_token_file)
        if not vault_addr or not has_token:
            raise RuntimeError(
                "Production Vault backend requires VAULT_ADDR and VAULT_TOKEN (or VAULT_TOKEN_FILE)."
            )

    if backend == "aws_kms" and not (aws_kms_key_id and aws_kms_key_id.strip()):
        raise RuntimeError("Production AWS KMS backend requires AWS_KMS_KEY_ID.")
