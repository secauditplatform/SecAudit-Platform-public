import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from jose import jwt
from unittest.mock import AsyncMock

from app.core.auth import (
    LOCAL_REFRESH_TOKEN_TYPE,
    LOCAL_TOKEN_TYPE,
    create_local_token,
    create_local_token_pair,
    refresh_local_tokens,
)
from app.core.config import Settings, settings
from app.core.passwords import hash_password
from app.main import app
from app.models import User, UserRole
from secaudit_core.security import (
    DEFAULT_SECRET_KEY,
    validate_bootstrap_admin_config,
    validate_production_secret_key,
)
from app.api.v1.routers import auth as auth_router


def _db_user(
    *,
    username: str = "alice",
    password: str = "correct-horse-battery",
    role: UserRole = UserRole.OPERATOR,
    is_active: bool = True,
) -> User:
    return User(
        id=1,
        username=username,
        email=f"{username}@example.test",
        hashed_password=hash_password(password),
        role=role,
        is_active=is_active,
    )


@pytest.fixture(autouse=True)
def _restore_auth_settings(monkeypatch: pytest.MonkeyPatch):
    async def _no_db_user(_db, _username, _password):
        return None

    monkeypatch.setattr(auth_router, "_authenticate_db_user", _no_db_user)
    original = {
        "auth_enabled": settings.auth_enabled,
        "local_auth_enabled": settings.local_auth_enabled,
        "local_auth_token_ttl_seconds": settings.local_auth_token_ttl_seconds,
        "local_auth_rate_limit_enabled": settings.local_auth_rate_limit_enabled,
        "console_enabled": settings.console_enabled,
        "bootstrap_admin_username": settings.bootstrap_admin_username,
        "bootstrap_admin_password": settings.bootstrap_admin_password,
        "bootstrap_admin_password_file": settings.bootstrap_admin_password_file,
        "bootstrap_admin_email": settings.bootstrap_admin_email,
    }
    settings.local_auth_rate_limit_enabled = False
    yield
    for key, value in original.items():
        setattr(settings, key, value)


def test_credentials_returns_401_when_auth_enabled(client: TestClient):
    settings.auth_enabled = True
    response = client.get("/api/v1/credentials")
    assert response.status_code == 401


def test_hosts_returns_401_when_auth_enabled(client: TestClient):
    settings.auth_enabled = True
    response = client.get("/api/v1/hosts")
    assert response.status_code == 401


def test_categories_list_returns_401_when_auth_enabled(client: TestClient):
    settings.auth_enabled = True
    response = client.get("/api/v1/categories")
    assert response.status_code == 401


def test_local_login_is_rejected_when_local_auth_disabled(client: TestClient):
    settings.auth_enabled = True
    settings.local_auth_enabled = False

    response = client.post(
        "/api/v1/auth/local",
        json={"username": "dev", "password": "dev"},
    )

    assert response.status_code == 403
    assert response.json()["detail"] == "Local login is disabled"


def test_fallback_dev_credentials_are_rejected(client: TestClient):
    """Builtin env fallback ``dev``/``dev`` is gone — unknown users get 401."""
    settings.auth_enabled = True
    settings.local_auth_enabled = True

    response = client.post(
        "/api/v1/auth/local",
        json={"username": "dev", "password": "dev"},
    )
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


def test_local_login_uses_database_user_role(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
):
    settings.auth_enabled = True
    settings.local_auth_enabled = True
    user = _db_user(role=UserRole.OPERATOR)

    async def _auth(_db, username, password):
        if username == user.username and password == "correct-horse-battery":
            return user
        return None

    monkeypatch.setattr(auth_router, "_authenticate_db_user", _auth)
    monkeypatch.setattr(auth_router, "log_audit_event", AsyncMock())

    response = client.post(
        "/api/v1/auth/local",
        json={"username": "alice", "password": "correct-horse-battery"},
    )
    assert response.status_code == 200

    body = response.json()
    token = body["access_token"]
    assert body["refresh_token"]
    assert body["expires_in"] == settings.local_auth_token_ttl_seconds
    payload = jwt.decode(token, settings.local_jwt_signing_key_effective, algorithms=["HS256"])
    assert payload["typ"] == LOCAL_TOKEN_TYPE
    assert payload["realm_access"]["roles"] == [UserRole.OPERATOR.value]
    assert payload["local_source"] == "database"
    assert "exp" in payload
    assert "iat" in payload


def test_local_token_rejects_expired_token(client: TestClient):
    from datetime import UTC, datetime, timedelta

    settings.auth_enabled = True
    settings.local_auth_enabled = True
    now = datetime.now(UTC)
    expired = jwt.encode(
        {
            "sub": "local:alice",
            "preferred_username": "alice",
            "realm_access": {"roles": [UserRole.ADMIN.value]},
            "typ": LOCAL_TOKEN_TYPE,
            "local_source": "database",
            "iat": int((now - timedelta(hours=2)).timestamp()),
            "exp": int((now - timedelta(hours=1)).timestamp()),
        },
        settings.local_jwt_signing_key_effective,
        algorithm="HS256",
    )

    me = client.get("/api/v1/credentials", headers={"Authorization": f"Bearer {expired}"})
    assert me.status_code == 401


def test_local_login_success_logs_audit_event(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    settings.auth_enabled = True
    settings.local_auth_enabled = True
    user = _db_user(role=UserRole.OPERATOR)

    async def _auth(_db, username, password):
        return user if username == "alice" and password == "correct-horse-battery" else None

    monkeypatch.setattr(auth_router, "_authenticate_db_user", _auth)
    logged = AsyncMock()
    monkeypatch.setattr(auth_router, "log_audit_event", logged)

    response = client.post(
        "/api/v1/auth/local",
        json={"username": "alice", "password": "correct-horse-battery"},
    )
    assert response.status_code == 200
    assert logged.await_count == 1
    assert logged.await_args.kwargs.get("outcome", "success") == "success"
    assert logged.await_args.kwargs["action"] == "auth.local_login"


def test_local_login_failure_logs_audit_event(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    settings.auth_enabled = True
    settings.local_auth_enabled = True
    logged = AsyncMock()
    monkeypatch.setattr(auth_router, "log_audit_event", logged)

    response = client.post("/api/v1/auth/local", json={"username": "alice", "password": "bad"})
    assert response.status_code == 401
    assert logged.await_count == 1
    assert logged.await_args.kwargs["outcome"] == "failed"
    assert logged.await_args.kwargs["action"] == "auth.local_login"


def test_local_refresh_token_issues_new_access_token(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
):
    settings.auth_enabled = True
    settings.local_auth_enabled = True
    user = _db_user(role=UserRole.OPERATOR)
    monkeypatch.setattr(auth_router, "log_audit_event", AsyncMock())

    async def _auth(_db, username, password):
        return user if username == "alice" and password == "correct-horse-battery" else None

    monkeypatch.setattr(auth_router, "_authenticate_db_user", _auth)

    async def _resolve_refresh(_db, token_user):
        from app.core.auth import AuthUser

        return (
            AuthUser(
                sub=f"local:{user.username}",
                username=user.username,
                roles=[user.role.value],
                auth_mode="local",
                local_source="database",
            ),
            "database",
        )

    monkeypatch.setattr(auth_router, "_resolve_refresh_user", _resolve_refresh)

    login = client.post(
        "/api/v1/auth/local",
        json={"username": "alice", "password": "correct-horse-battery"},
    )
    assert login.status_code == 200
    refresh_token = login.json()["refresh_token"]

    refreshed = client.post("/api/v1/auth/refresh", json={"refresh_token": refresh_token})
    assert refreshed.status_code == 200
    body = refreshed.json()
    assert body["access_token"]
    assert body["refresh_token"]
    payload = jwt.decode(body["access_token"], settings.local_jwt_signing_key_effective, algorithms=["HS256"])
    assert payload["typ"] == LOCAL_TOKEN_TYPE
    assert UserRole.OPERATOR.value in payload["realm_access"]["roles"]

    refresh_payload = jwt.decode(body["refresh_token"], settings.local_jwt_signing_key_effective, algorithms=["HS256"])
    assert refresh_payload["typ"] == LOCAL_REFRESH_TOKEN_TYPE


def test_local_refresh_rejects_access_token(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    settings.auth_enabled = True
    settings.local_auth_enabled = True
    monkeypatch.setattr(auth_router, "log_audit_event", AsyncMock())
    token = create_local_token("alice", [UserRole.ADMIN.value], local_source="database")
    response = client.post("/api/v1/auth/refresh", json={"refresh_token": token})
    assert response.status_code == 401


def test_local_refresh_rejects_environment_source_tokens(
    client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
):
    """Legacy env-backed local tokens must no longer refresh."""
    settings.auth_enabled = True
    settings.local_auth_enabled = True
    monkeypatch.setattr(auth_router, "log_audit_event", AsyncMock())
    pair = create_local_token_pair(
        "dev",
        [UserRole.ADMIN.value],
        local_source="environment",
    )
    response = client.post("/api/v1/auth/refresh", json={"refresh_token": pair.refresh_token})
    assert response.status_code == 401


def test_local_login_rate_limited(client: TestClient, monkeypatch: pytest.MonkeyPatch):
    settings.auth_enabled = True
    settings.local_auth_enabled = True
    settings.local_auth_rate_limit_enabled = True
    monkeypatch.setattr(auth_router, "log_audit_event", AsyncMock())

    async def _blocked(request, **kwargs):
        raise HTTPException(status_code=429, detail="Too many requests")

    monkeypatch.setattr("app.api.v1.routers.auth.enforce_rate_limit", _blocked)
    response = client.post("/api/v1/auth/local", json={"username": "dev", "password": "dev"})
    assert response.status_code == 429


def test_create_local_token_pair_roundtrip():
    pair = create_local_token_pair("alice", [UserRole.OPERATOR.value], local_source="database")
    refreshed = refresh_local_tokens(pair.refresh_token, [UserRole.OPERATOR.value])
    access = jwt.decode(refreshed.access_token, settings.local_jwt_signing_key_effective, algorithms=["HS256"])
    assert access["preferred_username"] == "alice"


def _refresh_db(user):
    db = AsyncMock()
    db.execute.return_value = type(
        "Result",
        (),
        {"scalar_one_or_none": lambda self: user},
    )()
    return db


@pytest.mark.asyncio
async def test_database_refresh_rejects_deleted_user():
    token_user = auth_router._decode_local_refresh_token(
        create_local_token_pair(
            "alice",
            [UserRole.ADMIN.value],
            local_source="database",
        ).refresh_token
    )
    assert token_user is not None
    with pytest.raises(HTTPException) as exc:
        await auth_router._resolve_refresh_user(_refresh_db(None), token_user)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_database_refresh_rejects_deactivated_user():
    db_user = User(
        username="alice",
        email="alice@example.test",
        hashed_password="unused",
        role=UserRole.ADMIN,
        is_active=False,
    )
    token_user = auth_router._decode_local_refresh_token(
        create_local_token_pair(
            "alice",
            [UserRole.ADMIN.value],
            local_source="database",
        ).refresh_token
    )
    assert token_user is not None
    with pytest.raises(HTTPException) as exc:
        await auth_router._resolve_refresh_user(_refresh_db(db_user), token_user)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_database_refresh_uses_current_downgraded_role():
    db_user = User(
        username="alice",
        email="alice@example.test",
        hashed_password="unused",
        role=UserRole.OPERATOR,
        is_active=True,
    )
    pair = create_local_token_pair(
        "alice",
        [UserRole.ADMIN.value],
        local_source="database",
    )
    token_user = auth_router._decode_local_refresh_token(pair.refresh_token)
    assert token_user is not None
    current_user, source = await auth_router._resolve_refresh_user(_refresh_db(db_user), token_user)
    refreshed = refresh_local_tokens(pair.refresh_token, current_user.roles, local_source=source)
    access = jwt.decode(refreshed.access_token, settings.local_jwt_signing_key_effective, algorithms=["HS256"])
    assert access["realm_access"]["roles"] == [UserRole.OPERATOR.value]


def test_local_token_decodes_without_keycloak_aud_iss_checks():
    token = create_local_token("alice", [UserRole.OPERATOR.value], local_source="database")
    payload = jwt.decode(token, settings.local_jwt_signing_key_effective, algorithms=["HS256"])
    assert payload["typ"] == LOCAL_TOKEN_TYPE
    assert UserRole.OPERATOR.value in payload["realm_access"]["roles"]


_STRONG_PRODUCTION_SECRET = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678abcdef90fedcba0987654321"


def _configure_production_secrets_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "secrets_backend", "aws_kms")
    monkeypatch.setattr(settings, "aws_kms_key_id", "arn:aws:kms:us-east-1:123456789012:key/test")


def test_validate_production_secret_key_rejects_default():
    with pytest.raises(RuntimeError, match="dev-secret-key"):
        validate_production_secret_key(DEFAULT_SECRET_KEY, "production")


@pytest.mark.parametrize(
    "placeholder",
    [
        "change-me-in-production-use-openssl-rand-hex-32",
        "change-me-in-production",
        "change-me",
        "<generate-with-openssl-rand-hex-32>",
    ],
)
def test_validate_production_secret_key_rejects_documented_placeholders(placeholder: str):
    with pytest.raises(RuntimeError, match="placeholder"):
        validate_production_secret_key(placeholder, "production")


def test_validate_production_secret_key_rejects_short_key():
    with pytest.raises(RuntimeError, match="at least 32"):
        validate_production_secret_key("custom-production-key-too-short", "production")


def test_validate_production_secret_key_rejects_low_entropy_key():
    with pytest.raises(RuntimeError, match="entropy"):
        validate_production_secret_key("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "production")


def test_validate_production_secret_key_allows_strong_random_key():
    validate_production_secret_key(_STRONG_PRODUCTION_SECRET, "production")


def test_validate_production_secret_key_allows_default_in_development():
    validate_production_secret_key(DEFAULT_SECRET_KEY, "development")
    validate_production_secret_key(
        "change-me-in-production-use-openssl-rand-hex-32",
        "development",
    )


def test_local_auth_is_disabled_by_default():
    configured = Settings(
        _env_file=None,
        local_auth_enabled=False,
    )

    assert Settings.model_fields["local_auth_enabled"].default is False
    assert configured.local_auth_enabled is False
    assert "local_auth_username" not in Settings.model_fields
    assert "local_auth_password" not in Settings.model_fields


def test_settings_have_no_env_fallback_credentials():
    assert "local_auth_username" not in Settings.model_fields
    assert "local_auth_password" not in Settings.model_fields
    assert "local_auth_password_file" not in Settings.model_fields
    assert "local_auth_role" not in Settings.model_fields


@pytest.mark.parametrize(
    ("username", "password", "expected_error"),
    [
        ("dev", "a-secure-password-value", "username"),
        ("platform-admin", "dev", "password"),
        ("admin", "a-secure-password-value", "username"),
        ("platform-admin", "password", "password"),
        ("<username>", "a-secure-password-value", "username"),
        ("platform-admin", "<password-placeholder>", "password"),
    ],
)
def test_bootstrap_rejects_fallbacks_and_placeholders(
    username: str,
    password: str,
    expected_error: str,
):
    with pytest.raises(RuntimeError, match=expected_error):
        validate_bootstrap_admin_config(
            app_env="development",
            username=username,
            password=password,
            password_from_secret_file=False,
            direct_password_configured=True,
        )


def test_production_bootstrap_rejects_direct_environment_password():
    secret = "do-not-include-this-secret-value"
    with pytest.raises(RuntimeError) as error:
        validate_bootstrap_admin_config(
            app_env="production",
            username="platform-admin",
            password=secret,
            password_from_secret_file=False,
            direct_password_configured=True,
        )

    assert secret not in str(error.value)


def test_production_bootstrap_accepts_secure_secret_file(tmp_path):
    secret_file = tmp_path / "bootstrap-admin-password"
    secret_file.write_text("correct-horse-battery-staple", encoding="utf-8")
    configured = Settings(
        _env_file=None,
        app_env="production",
        bootstrap_admin_username="platform-admin",
        bootstrap_admin_password=None,
        bootstrap_admin_password_file=str(secret_file),
    )

    configured.validate_bootstrap_admin_security()
    assert configured.get_bootstrap_admin_password() == "correct-horse-battery-staple"


def test_development_bootstrap_allows_non_placeholder_credentials():
    configured = Settings(
        _env_file=None,
        app_env="development",
        bootstrap_admin_username="platform-admin",
        bootstrap_admin_password="correct-horse-battery",
    )

    configured.validate_bootstrap_admin_security()


def test_api_startup_rejects_insecure_production_bootstrap(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "secret_key", _STRONG_PRODUCTION_SECRET)
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "api_debug", False)
    monkeypatch.setattr(settings, "bootstrap_admin_username", "dev")
    monkeypatch.setattr(settings, "bootstrap_admin_password", "dev")
    monkeypatch.setattr(settings, "bootstrap_admin_password_file", None)
    _configure_production_secrets_backend(monkeypatch)

    with pytest.raises(RuntimeError, match="fallback or placeholder"):
        with TestClient(app):
            pass


def test_api_startup_accepts_secure_production_without_bootstrap(
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(settings, "secret_key", _STRONG_PRODUCTION_SECRET)
    monkeypatch.setattr(settings, "auth_enabled", True)
    monkeypatch.setattr(settings, "api_debug", False)
    monkeypatch.setattr(settings, "bootstrap_admin_username", None)
    monkeypatch.setattr(settings, "bootstrap_admin_password", None)
    monkeypatch.setattr(settings, "bootstrap_admin_password_file", None)
    monkeypatch.setattr(settings, "local_auth_enabled", True)
    _configure_production_secrets_backend(monkeypatch)

    with TestClient(app) as production_client:
        assert production_client.get("/api/v1/health/live").status_code == 200


def test_keycloak_issuer_url_splits_jwks_host_from_token_issuer():
    settings.keycloak_url = "http://keycloak:8080"
    settings.keycloak_realm = "secaudit"
    settings.keycloak_issuer = "http://localhost:8080/realms/secaudit"

    assert settings.keycloak_jwks_url == (
        "http://keycloak:8080/realms/secaudit/protocol/openid-connect/certs"
    )
    assert settings.keycloak_issuer_url == "http://localhost:8080/realms/secaudit"


def test_dashboard_overview_rbac_for_read_only_roles(
    client: TestClient,
    auth_headers: dict[str, str],
    operator_headers: dict[str, str],
    admin_headers: dict[str, str],
):
    """Viewer/auditor can load overview data except operator-only credentials."""
    viewer_credentials = client.get("/api/v1/credentials", headers=auth_headers)
    assert viewer_credentials.status_code == 403

    viewer_profiles = client.get("/api/v1/profiles", headers=auth_headers)
    assert viewer_profiles.status_code == 200

    viewer_jobs = client.get("/api/v1/jobs", headers=auth_headers)
    assert viewer_jobs.status_code == 200

    operator_credentials = client.get("/api/v1/credentials", headers=operator_headers)
    assert operator_credentials.status_code == 200

    admin_credentials = client.get("/api/v1/credentials", headers=admin_headers)
    assert admin_credentials.status_code == 200
