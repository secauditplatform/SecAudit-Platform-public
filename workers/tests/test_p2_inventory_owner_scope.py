"""Inventory host linking must be scoped by scan owner and skip duplicates."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from sqlalchemy.orm import Session

from app.inventory_scan_runner import _apply_port_info_chunk, _find_existing_host
from secaudit_core.models import Host


class _FakeScalars:
    def __init__(self, rows):
        self._rows = list(rows)

    def __iter__(self):
        return iter(self._rows)

    def all(self):
        return list(self._rows)

    def first(self):
        return self._rows[0] if self._rows else None


class _FakeResult:
    def __init__(self, rows):
        self._rows = rows

    def scalars(self):
        return _FakeScalars(self._rows)


def test_inventory_does_not_link_other_owners_host(monkeypatch):
    created: list[Host] = []
    row = SimpleNamespace(
        ip_address="10.0.0.5",
        resolved_hostname=None,
        open_ports=None,
        is_active=False,
        host_id=None,
    )
    scan = SimpleNamespace(id=1, owner_sub="tenant-a", hosts_created=0)
    calls = {"n": 0}

    def fake_execute(_stmt):
        calls["n"] += 1
        if calls["n"] == 1:
            return _FakeResult([row])
        # Owner-scoped Host lookup: empty → create new host for tenant-a
        return _FakeResult([])

    db = MagicMock(spec=Session)
    db.execute.side_effect = fake_execute

    def fake_add(obj):
        created.append(obj)
        obj.id = 99

    db.add.side_effect = fake_add

    monkeypatch.setattr(
        "app.inventory_scan_runner.infer_host_defaults",
        lambda _ports: (22, "linux"),
    )
    monkeypatch.setattr(
        "app.inventory_scan_runner.host_name_for_ip",
        lambda ip, _hn: f"host-{ip}",
    )

    hosts_created = _apply_port_info_chunk(
        db,
        scan,
        ["10.0.0.5"],
        {"10.0.0.5": {"open_ports": [22], "hostname": None}},
    )

    assert hosts_created == 1
    assert len(created) == 1
    assert created[0].owner_sub == "tenant-a"
    assert created[0].hostname == "10.0.0.5"
    assert row.host_id == 99


def test_inventory_reuses_same_owner_host(monkeypatch):
    existing = Host(
        id=42,
        name="mine",
        hostname="10.0.0.8",
        port=22,
        os_type="linux",
        is_active=True,
        owner_sub="tenant-a",
    )
    row = SimpleNamespace(
        ip_address="10.0.0.8",
        resolved_hostname=None,
        open_ports=None,
        is_active=False,
        host_id=None,
    )
    scan = SimpleNamespace(id=2, owner_sub="tenant-a", hosts_created=0)
    calls = {"n": 0}

    def fake_execute(_stmt):
        calls["n"] += 1
        if calls["n"] == 1:
            return _FakeResult([row])
        return _FakeResult([existing])

    db = MagicMock(spec=Session)
    db.execute.side_effect = fake_execute

    hosts_created = _apply_port_info_chunk(
        db,
        scan,
        ["10.0.0.8"],
        {"10.0.0.8": {"open_ports": [22], "hostname": None}},
    )
    assert hosts_created == 0
    assert row.host_id == 42
    db.add.assert_not_called()


def test_inventory_reuses_host_matched_by_resolved_hostname(monkeypatch):
    existing = Host(
        id=55,
        name="web01",
        hostname="web01.corp.local",
        port=22,
        os_type="linux",
        is_active=True,
        owner_sub="tenant-a",
    )
    row = SimpleNamespace(
        ip_address="10.0.0.20",
        resolved_hostname="web01.corp.local",
        open_ports=None,
        is_active=False,
        host_id=None,
    )
    scan = SimpleNamespace(id=3, owner_sub="tenant-a", hosts_created=0)
    calls = {"n": 0}

    def fake_execute(_stmt):
        calls["n"] += 1
        if calls["n"] == 1:
            return _FakeResult([row])
        return _FakeResult([existing])

    db = MagicMock(spec=Session)
    db.execute.side_effect = fake_execute

    hosts_created = _apply_port_info_chunk(
        db,
        scan,
        ["10.0.0.20"],
        {"10.0.0.20": {"open_ports": [22], "hostname": "web01.corp.local"}},
    )
    assert hosts_created == 0
    assert row.host_id == 55
    db.add.assert_not_called()


def test_inventory_reuses_and_claims_unowned_host(monkeypatch):
    existing = Host(
        id=77,
        name="legacy",
        hostname="10.0.0.30",
        port=22,
        os_type="linux",
        is_active=True,
        owner_sub=None,
    )
    row = SimpleNamespace(
        ip_address="10.0.0.30",
        resolved_hostname=None,
        open_ports=None,
        is_active=False,
        host_id=None,
    )
    scan = SimpleNamespace(id=4, owner_sub="tenant-a", hosts_created=0)
    calls = {"n": 0}

    def fake_execute(_stmt):
        calls["n"] += 1
        if calls["n"] == 1:
            return _FakeResult([row])
        return _FakeResult([existing])

    db = MagicMock(spec=Session)
    db.execute.side_effect = fake_execute

    hosts_created = _apply_port_info_chunk(
        db,
        scan,
        ["10.0.0.30"],
        {"10.0.0.30": {"open_ports": [22], "hostname": None}},
    )
    assert hosts_created == 0
    assert row.host_id == 77
    assert existing.owner_sub == "tenant-a"
    db.add.assert_not_called()


def test_find_existing_host_prefers_same_owner_over_unowned():
    owned = Host(
        id=1,
        name="owned",
        hostname="10.0.0.40",
        port=22,
        os_type="linux",
        is_active=True,
        owner_sub="tenant-a",
    )
    unowned = Host(
        id=2,
        name="unowned",
        hostname="10.0.0.40",
        port=22,
        os_type="linux",
        is_active=True,
        owner_sub=None,
    )
    db = MagicMock(spec=Session)
    db.execute.return_value = _FakeResult([unowned, owned])

    found = _find_existing_host(
        db,
        owner_sub="tenant-a",
        ip="10.0.0.40",
        resolved_hostname=None,
    )
    assert found is owned
