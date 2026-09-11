"""Regression tests for application P1 hardening."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from jose import JWTError, jwt

from app.core.auth import _decode_keycloak_token_with_jwks, create_local_token
from app.core.config import settings
from app.models import UserRole
from secaudit_core.package_paths import resolve_script_under_package
from secaudit_core.security import validate_production_runtime_config


def test_validate_production_runtime_config_rejects_disabled_auth():
    with pytest.raises(RuntimeError, match="AUTH_ENABLED=false"):
        validate_production_runtime_config(
            app_env="production",
            auth_enabled=False,
            api_debug=False,
        )


def test_validate_production_runtime_config_rejects_api_debug():
    with pytest.raises(RuntimeError, match="API_DEBUG=true"):
        validate_production_runtime_config(
            app_env="production",
            auth_enabled=True,
            api_debug=True,
        )


def test_validate_production_runtime_config_allows_development_defaults():
    validate_production_runtime_config(
        app_env="development",
        auth_enabled=False,
        api_debug=True,
    )


def test_keycloak_jwt_rejects_unsupported_algorithm():
    token = jwt.encode(
        {"sub": "user-1", "realm_access": {"roles": ["viewer"]}},
        "secret",
        algorithm="HS256",
        headers={"kid": "k1"},
    )
    with pytest.raises(JWTError, match="Unsupported JWT algorithm"):
        _decode_keycloak_token_with_jwks(token, {"keys": [{"kid": "k1"}]})


def test_resolve_script_under_package_rejects_traversal(tmp_path: Path):
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "audit.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (tmp_path / "outside.sh").write_text("#!/bin/sh\n", encoding="utf-8")

    resolved = resolve_script_under_package(package, "audit.sh")
    assert resolved.name == "audit.sh"

    with pytest.raises(ValueError, match="must stay inside package"):
        resolve_script_under_package(package, "../outside.sh")


@pytest.fixture(autouse=True)
def _console_embedded_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "console_sandbox_enabled", False)
    monkeypatch.setattr(settings, "console_enabled", True)
    monkeypatch.setattr(settings, "console_allow_in_production", True)


def test_ws_console_authenticates_via_first_message(client: TestClient):
    token = create_local_token("operator", [UserRole.OPERATOR.value])
    with client.websocket_connect("/api/v1/ws/console") as ws:
        ws.send_text(json.dumps({"type": "auth", "token": token}))
        welcome = ws.receive_text()
        assert "SecAudit Console" in welcome
