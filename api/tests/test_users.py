from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.api.v1.routers import auth as auth_router
from app.api.v1.routers import users as users_router
from app.core.auth import AuthUser, create_local_token
from app.core.config import settings
from app.core.passwords import hash_password, verify_password
from app.main import app
from app.models import User, UserRole
from app.schemas import UserCreate, UserUpdate


def test_hash_and_verify_password_roundtrip():
    hashed = hash_password("secret-pass-1")
    assert verify_password("secret-pass-1", hashed)
    assert not verify_password("wrong", hashed)


def test_users_list_requires_admin(client: TestClient):
    settings.auth_enabled = True
    viewer_token = create_local_token("viewer", [UserRole.OPERATOR.value])
    response = client.get("/api/v1/users", headers={"Authorization": f"Bearer {viewer_token}"})
    assert response.status_code == 403


def test_users_list_requires_auth(client: TestClient):
    settings.auth_enabled = True
    response = client.get("/api/v1/users")
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_create_user_hashes_password(monkeypatch):
    saved: list[User] = []

    class _Db:
        def add(self, obj):
            saved.append(obj)

        async def flush(self):
            if saved:
                saved[0].id = 1
                saved[0].created_at = datetime.now(UTC)

        async def refresh(self, _obj):
            return None

    async def _execute(_stmt):
        return type("R", (), {"scalar_one_or_none": lambda self: None})()

    db = _Db()
    db.execute = _execute
    logged = AsyncMock()
    monkeypatch.setattr(users_router, "log_audit_event", logged)

    result = await users_router.create_user(
        data=UserCreate(
            username="alice",
            email="alice@example.com",
            full_name="Alice",
            role=UserRole.OPERATOR,
            password="password123",
        ),
        request=type("Req", (), {"headers": {}, "client": None})(),
        db=db,
        actor=AuthUser(sub="local:admin", username="admin", roles=[UserRole.ADMIN.value]),
    )
    assert result.username == "alice"
    assert saved[0].hashed_password != "password123"
    assert verify_password("password123", saved[0].hashed_password)


@pytest.mark.asyncio
async def test_update_user_blocks_self_deactivate():
    user = User(
        id=1,
        username="admin",
        email="admin@example.com",
        hashed_password=hash_password("password123"),
        role=UserRole.ADMIN,
        is_active=True,
        created_at=datetime.now(UTC),
    )

    class _Db:
        async def get(self, _model, user_id):
            return user if user_id == 1 else None

        async def flush(self):
            return None

        async def refresh(self, _obj):
            return None

    db = _Db()
    with pytest.raises(HTTPException) as exc:
        await users_router.update_user(
            user_id=1,
            data=UserUpdate(is_active=False),
            request=type("Req", (), {"headers": {}, "client": None})(),
            db=db,
            actor=AuthUser(sub="local:admin", username="admin", roles=[UserRole.ADMIN.value]),
        )
    assert exc.value.status_code == 409


@pytest.mark.asyncio
async def test_authenticate_db_user_success():
    user = User(
        id=1,
        username="alice",
        email="alice@example.com",
        hashed_password=hash_password("password123"),
        role=UserRole.OPERATOR,
        is_active=True,
        created_at=datetime.now(UTC),
    )

    class _Db:
        async def execute(self, _stmt):
            return type("R", (), {"scalar_one_or_none": lambda self: user})()

    authenticated = await auth_router._authenticate_db_user(_Db(), "alice", "password123")
    assert authenticated is user


@pytest.mark.asyncio
async def test_authenticate_db_user_rejects_inactive():
    user = User(
        id=1,
        username="alice",
        email="alice@example.com",
        hashed_password=hash_password("password123"),
        role=UserRole.OPERATOR,
        is_active=False,
        created_at=datetime.now(UTC),
    )

    class _Db:
        async def execute(self, _stmt):
            return type("R", (), {"scalar_one_or_none": lambda self: user})()

    authenticated = await auth_router._authenticate_db_user(_Db(), "alice", "password123")
    assert authenticated is None
