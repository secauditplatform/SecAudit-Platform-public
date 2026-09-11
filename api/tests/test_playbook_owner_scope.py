"""Playbook object RBAC (owner_sub)."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi import HTTPException

from app.api.v1.routers import playbooks as playbooks_router
from app.core.auth import AuthUser
from app.models import Playbook, PlaybookKind, UserRole
from app.schemas import PlaybookUpdate


def _playbook(**kwargs) -> Playbook:
    defaults = {
        "id": 1,
        "name": "linux-baseline",
        "content": "---\n- hosts: all\n  tasks: []\n",
        "is_active": True,
        "owner_sub": "local:alice",
        "platform": "linux",
        "kind": PlaybookKind.USER,
    }
    defaults.update(kwargs)
    return Playbook(**defaults)


@pytest.mark.asyncio
async def test_update_playbook_denies_foreign_engineer():
    playbook = _playbook(owner_sub="local:bob")
    user = AuthUser(sub="local:alice", username="alice", roles=[UserRole.OPERATOR.value])
    db = AsyncMock()

    class _Result:
        def scalar_one_or_none(self):
            return playbook

    db.execute = AsyncMock(return_value=_Result())

    with pytest.raises(HTTPException) as exc:
        await playbooks_router.update_playbook(
            1,
            PlaybookUpdate(content="---\n"),
            MagicMock(),
            db,
            user,
        )
    assert exc.value.status_code == 404


@pytest.mark.asyncio
async def test_list_playbooks_applies_owner_scope(monkeypatch):
    user = AuthUser(sub="local:alice", username="alice", roles=[UserRole.OPERATOR.value])
    db = AsyncMock()
    scoped = {"called": False}

    def _applies_engineer_scope(roles, enabled=True):
        scoped["called"] = True
        return True

    monkeypatch.setattr(playbooks_router, "applies_engineer_scope", _applies_engineer_scope)
    monkeypatch.setattr(playbooks_router, "rbac_enabled", lambda: True)

    class _Scalars:
        def all(self):
            return []

    class _Result:
        def scalars(self):
            return _Scalars()

    db.execute = AsyncMock(return_value=_Result())

    result = await playbooks_router.list_playbooks(
        db=db,
        user=user,
        scope=None,
        platform=None,
        kind=None,
    )
    assert scoped["called"]
    assert result == []
    stmt = db.execute.await_args[0][0]
    assert "owner_sub" in str(stmt)
