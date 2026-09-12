"""Local JWT signing key isolation and DB revalidation."""

from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException
from jose import jwt

from app.core import auth as auth_module
from app.core.auth import AuthUser, LOCAL_TOKEN_TYPE, _decode_local_token, create_local_token
from app.core.config import settings
from app.models import UserRole


def test_local_token_uses_dedicated_signing_key(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "local_jwt_signing_key", "dedicated-local-jwt-key-32bytes!!")
    monkeypatch.setattr(settings, "secret_key", "other-secret-used-for-fernet-only!!")
    token = create_local_token("alice", [UserRole.OPERATOR.value], local_source="database")
    with pytest.raises(Exception):
        jwt.decode(token, settings.secret_key, algorithms=["HS256"])
    payload = jwt.decode(token, settings.local_jwt_signing_key_effective, algorithms=["HS256"])
    assert payload["typ"] == LOCAL_TOKEN_TYPE
    assert _decode_local_token(token) is not None


@pytest.mark.asyncio
async def test_revalidate_local_user_rejects_inactive(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "local_auth_revalidate_from_db", True)
    user = AuthUser(
        sub="local:alice",
        username="alice",
        roles=[UserRole.ADMIN.value],
        auth_mode="local",
        local_source="database",
    )
    inactive = MagicMock(is_active=False, username="alice", role=UserRole.OPERATOR)

    class _Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def execute(self, _stmt):
            return MagicMock(scalar_one_or_none=lambda: inactive)

    with patch("app.core.database.async_session", return_value=_Session()):
        with pytest.raises(HTTPException) as exc:
            await auth_module._revalidate_local_user_from_db(user)
    assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_revalidate_local_user_refreshes_roles(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "local_auth_revalidate_from_db", True)
    user = AuthUser(
        sub="local:alice",
        username="alice",
        roles=[UserRole.ADMIN.value],
        auth_mode="local",
        local_source="database",
    )
    active = MagicMock(is_active=True, username="alice", role=UserRole.OPERATOR)

    class _Session:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return None

        async def execute(self, _stmt):
            return MagicMock(scalar_one_or_none=lambda: active)

    with patch("app.core.database.async_session", return_value=_Session()):
        refreshed = await auth_module._revalidate_local_user_from_db(user)
    assert refreshed.roles == [UserRole.OPERATOR.value]
    assert refreshed.local_source == "database"
