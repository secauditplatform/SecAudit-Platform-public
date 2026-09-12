import os
import sys
from pathlib import Path

# Ensure /app (api package root) is importable when pytest changes rootdir.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import asyncio

import pytest
from fastapi.testclient import TestClient

from app.core.auth import create_local_token
from app.main import app
from app.models import UserRole

# Skip Alembic on TestClient startup (unit tests do not require Postgres).
# Force override: compose sets SKIP_MIGRATIONS=0 for the running API container.
os.environ["SKIP_MIGRATIONS"] = "1"


def _dispose_async_engine() -> None:
    """Drop pooled asyncpg connections bound to a closed TestClient event loop."""
    from app.core.database import engine

    async def _dispose() -> None:
        await engine.dispose()

    try:
        asyncio.run(_dispose())
    except RuntimeError:
        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(_dispose())
        finally:
            loop.close()


@pytest.fixture(autouse=True)
def _reset_async_engine_pool():
    yield
    _dispose_async_engine()


@pytest.fixture(autouse=True)
def _enable_local_auth_for_api_tokens():
    """Allow create_local_token() bearer headers in router tests."""
    from app.core.config import settings

    original = {
        "auth_enabled": settings.auth_enabled,
        "local_auth_enabled": settings.local_auth_enabled,
        "local_auth_revalidate_from_db": settings.local_auth_revalidate_from_db,
    }
    settings.auth_enabled = True
    settings.local_auth_enabled = True
    # Unit tests mint JWTs without a User row; skip DB revalidation here.
    settings.local_auth_revalidate_from_db = False
    yield
    for key, value in original.items():
        setattr(settings, key, value)


@pytest.fixture
def client() -> TestClient:
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def auth_headers() -> dict[str, str]:
    token = create_local_token("tester", [UserRole.OPERATOR.value])
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def operator_headers() -> dict[str, str]:
    token = create_local_token("operator", [UserRole.OPERATOR.value])
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def engineer_headers() -> dict[str, str]:
    token = create_local_token("engineer", [UserRole.OPERATOR.value])
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_headers() -> dict[str, str]:
    token = create_local_token("admin", [UserRole.ADMIN.value])
    return {"Authorization": f"Bearer {token}"}
