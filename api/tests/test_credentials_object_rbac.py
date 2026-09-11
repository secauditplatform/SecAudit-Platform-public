"""Object RBAC for credentials and host credential attachment."""

from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from app.api.v1.routers import credentials, hosts
from app.core.auth import AuthUser
from app.models import Credential, Host, UserRole
from app.schemas import HostUpdate
from app.services import object_rbac as object_rbac_service


@pytest.mark.asyncio
async def test_assert_credential_visible_allows_shared_via_host():
    credential = Credential(
        id=3,
        name="shared",
        credential_type="ssh_password",
        username="root",
        encrypted_secret="enc",
        owner_sub="local:operator",
    )
    fake_db = AsyncMock()

    async def _get(model, pk):
        if model is Credential and pk == 3:
            return credential
        return None

    async def _execute(_stmt):
        return type("R", (), {"scalar_one_or_none": lambda self: 99})()

    fake_db.get = _get
    fake_db.execute = _execute

    result = await object_rbac_service.assert_credential_visible(
        fake_db,
        AuthUser(sub="local:eng1", username="eng1", roles=[UserRole.OPERATOR.value]),
        3,
    )
    assert result.id == 3


@pytest.mark.asyncio
async def test_assert_credential_visible_denies_foreign_credential():
    credential = Credential(
        id=3,
        name="foreign",
        credential_type="ssh_password",
        username="root",
        encrypted_secret="enc",
        owner_sub="local:bob",
    )
    fake_db = AsyncMock()
    fake_db.get = AsyncMock(return_value=credential)
    fake_db.execute = AsyncMock(
        return_value=type("R", (), {"scalar_one_or_none": lambda self: None})()
    )

    with pytest.raises(HTTPException) as exc:
        await object_rbac_service.assert_credential_visible(
            fake_db,
            AuthUser(sub="local:alice", username="alice", roles=[UserRole.OPERATOR.value]),
            3,
        )
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_list_credentials_applies_shared_scope_for_engineer(monkeypatch):
    fake_db = AsyncMock()
    captured: dict[str, str] = {}

    async def _execute(stmt):
        captured["sql"] = str(stmt)
        return type("R", (), {"scalars": lambda self: type("S", (), {"all": lambda self: []})()})()

    fake_db.execute = _execute
    monkeypatch.setattr(credentials, "log_audit_event", AsyncMock())

    await credentials.list_credentials(
        request=AsyncMock(),
        db=fake_db,
        user=AuthUser(sub="local:eng1", username="eng1", roles=[UserRole.OPERATOR.value]),
    )
    assert "credentials.owner_sub" in captured["sql"]
    assert "hosts.credential_id" in captured["sql"]
    assert "is_ephemeral" in captured["sql"]


@pytest.mark.asyncio
async def test_update_host_rejects_foreign_credential_attach(monkeypatch):
    monkeypatch.setattr(hosts, "log_audit_event", AsyncMock())

    host = Host(
        id=1,
        name="h1",
        hostname="10.0.0.1",
        port=22,
        is_active=True,
        owner_sub="local:alice",
    )
    foreign = Credential(
        id=9,
        name="bob-cred",
        credential_type="ssh_password",
        username="root",
        encrypted_secret="enc",
        owner_sub="local:bob",
    )
    fake_db = AsyncMock()
    fake_db.get = AsyncMock(side_effect=lambda model, pk: host if pk == 1 else foreign if pk == 9 else None)
    fake_db.flush = AsyncMock()
    fake_db.execute = AsyncMock(
        return_value=type(
            "R",
            (),
            {"scalar_one": lambda self: host, "scalar_one_or_none": lambda self: host},
        )()
    )

    with pytest.raises(HTTPException) as exc:
        await hosts.update_host(
            host_id=1,
            data=HostUpdate(credential_id=9),
            request=AsyncMock(),
            db=fake_db,
            user=AuthUser(sub="local:alice", username="alice", roles=[UserRole.OPERATOR.value]),
        )
    assert exc.value.status_code == 404
