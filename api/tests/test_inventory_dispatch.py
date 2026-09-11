"""Inventory scan dispatch via transactional outbox."""

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest

from app.api.v1.routers import inventory as inventory_router
from app.core.auth import AuthUser
from app.models import InventoryScan, JobStatus, UserRole
from app.schemas import InventoryScanCreate


@pytest.mark.asyncio
async def test_start_inventory_scan_uses_outbox_dispatch(monkeypatch):
    captured: list[InventoryScan] = []
    outbox_ids: list[int] = []

    fake_db = AsyncMock()

    async def _flush():
        return None

    async def _refresh(obj):
        if isinstance(obj, InventoryScan) and obj.id is None:
            obj.id = 42
        if isinstance(obj, InventoryScan):
            obj.hosts_found = 0
            obj.hosts_created = 0
            obj.created_at = datetime.now(UTC)

    async def _commit():
        return None

    async def _get(_model, scan_id):
        return captured[0] if captured and scan_id == 42 else None

    def _add(scan):
        captured.append(scan)

    fake_db.flush = _flush
    fake_db.refresh = _refresh
    fake_db.commit = _commit
    fake_db.get = _get
    fake_db.add = _add

    async def _enqueue(_db, **_kwargs):
        outbox_ids.append(99)
        return type("Outbox", (), {"id": 99})()

    async def _commit_dispatch(_db, *, outbox_id, pending_entity):
        return None

    monkeypatch.setattr(inventory_router, "enqueue_run_dispatch", _enqueue)
    monkeypatch.setattr(inventory_router, "commit_and_try_dispatch", _commit_dispatch)

    user = AuthUser(sub="local:eng1", username="eng1", roles=[UserRole.OPERATOR.value])
    result = await inventory_router.start_inventory_scan(
        InventoryScanCreate(target="10.0.0.0/30"),
        db=fake_db,
        user=user,
    )

    assert outbox_ids == [99]
    assert captured[0].owner_sub == "local:eng1"
    assert result.status == JobStatus.PENDING
