"""Host credential link helpers."""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from app.services.host_credentials import link_host_credential, replace_host_credentials


@pytest.mark.asyncio
async def test_replace_host_credentials_sets_primary_and_links(monkeypatch):
    host = SimpleNamespace(id=1, credential_id=None, credential_links=[])
    cred_password = SimpleNamespace(id=10, owner_sub="local:alice")
    cred_key = SimpleNamespace(id=11, owner_sub="local:alice")

    async def _get(model, pk):
        return {10: cred_password, 11: cred_key}.get(pk)

    monkeypatch.setattr(
        "app.services.host_credentials.assert_credential_attachable",
        lambda *_args, **_kwargs: None,
    )
    db = AsyncMock()
    db.get = AsyncMock(side_effect=_get)
    async def _execute(_stmt):
        host.credential_links.clear()
        return AsyncMock()

    db.execute = AsyncMock(side_effect=_execute)
    db.add = lambda item: host.credential_links.append(item)

    user = SimpleNamespace(sub="local:alice", roles=["engineer"])
    await replace_host_credentials(db, host, user, [10, 11])

    assert host.credential_id == 10
    assert len(host.credential_links) == 2


@pytest.mark.asyncio
async def test_link_host_credential_appends_without_duplicates(monkeypatch):
    link = SimpleNamespace(credential_id=10, sort_order=0)
    host = SimpleNamespace(id=1, credential_id=10, credential_links=[link])
    cred_key = SimpleNamespace(id=11, owner_sub="local:alice")

    monkeypatch.setattr(
        "app.services.host_credentials.assert_credential_attachable",
        lambda *_args, **_kwargs: None,
    )

    async def _get(model, pk):
        if pk == 11:
            return cred_key
        if pk == 10:
            return SimpleNamespace(id=10, owner_sub="local:alice")
        return None

    db = AsyncMock()
    db.get = AsyncMock(side_effect=_get)
    async def _execute(_stmt):
        host.credential_links.clear()
        return AsyncMock()

    db.execute = AsyncMock(side_effect=_execute)
    db.add = lambda item: host.credential_links.append(item)

    user = SimpleNamespace(sub="local:alice", roles=["engineer"])
    await link_host_credential(db, host, user, 11)

    assert host.credential_id == 10
    assert [item.credential_id for item in host.credential_links] == [10, 11]


@pytest.mark.asyncio
async def test_replace_host_credentials_rejects_missing_credential(monkeypatch):
    host = SimpleNamespace(id=1, credential_id=None, credential_links=[])
    monkeypatch.setattr(
        "app.services.host_credentials.assert_credential_attachable",
        lambda *_args, **_kwargs: None,
    )
    db = AsyncMock()
    db.get = AsyncMock(return_value=None)
    db.execute = AsyncMock()

    user = SimpleNamespace(sub="local:alice", roles=["engineer"])
    with pytest.raises(HTTPException) as exc:
        await replace_host_credentials(db, host, user, [99])
    assert exc.value.status_code == 404
