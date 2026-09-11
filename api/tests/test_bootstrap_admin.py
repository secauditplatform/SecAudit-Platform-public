import pytest
from unittest.mock import AsyncMock

from app.core.config import settings
from app.core.passwords import verify_password
from app.models import User, UserRole
from app.services import bootstrap_admin as bootstrap_module


@pytest.fixture(autouse=True)
def _restore_bootstrap_settings():
    original = {
        "bootstrap_admin_username": settings.bootstrap_admin_username,
        "bootstrap_admin_password": settings.bootstrap_admin_password,
        "bootstrap_admin_password_file": settings.bootstrap_admin_password_file,
        "bootstrap_admin_email": settings.bootstrap_admin_email,
        "app_env": settings.app_env,
    }
    yield
    for key, value in original.items():
        setattr(settings, key, value)


@pytest.mark.asyncio
async def test_bootstrap_skipped_when_unset():
    settings.bootstrap_admin_username = None
    settings.bootstrap_admin_password = None
    settings.bootstrap_admin_password_file = None

    created = await bootstrap_module.maybe_bootstrap_admin(AsyncMock())
    assert created is False


@pytest.mark.asyncio
async def test_bootstrap_creates_first_admin_when_empty():
    settings.app_env = "development"
    settings.bootstrap_admin_username = "platform-admin"
    settings.bootstrap_admin_password = "correct-horse-battery"
    settings.bootstrap_admin_email = "platform-admin@example.test"

    saved: list[User] = []

    class _Db:
        def add(self, obj):
            saved.append(obj)

        async def flush(self):
            saved[0].id = 42

        async def execute(self, _stmt):
            return type("R", (), {"scalar_one": lambda self: 0})()

    created = await bootstrap_module.maybe_bootstrap_admin(_Db())
    assert created is True
    assert len(saved) == 1
    assert saved[0].username == "platform-admin"
    assert saved[0].role == UserRole.ADMIN
    assert verify_password("correct-horse-battery", saved[0].hashed_password)


@pytest.mark.asyncio
async def test_bootstrap_skipped_when_users_exist():
    settings.app_env = "development"
    settings.bootstrap_admin_username = "platform-admin"
    settings.bootstrap_admin_password = "correct-horse-battery"

    class _Db:
        def add(self, _obj):
            raise AssertionError("must not create user")

        async def execute(self, _stmt):
            return type("R", (), {"scalar_one": lambda self: 3})()

    created = await bootstrap_module.maybe_bootstrap_admin(_Db())
    assert created is False


@pytest.mark.asyncio
async def test_bootstrap_rejects_dev_credentials():
    settings.app_env = "development"
    settings.bootstrap_admin_username = "dev"
    settings.bootstrap_admin_password = "dev"

    with pytest.raises(RuntimeError, match="fallback or placeholder"):
        await bootstrap_module.maybe_bootstrap_admin(AsyncMock())
