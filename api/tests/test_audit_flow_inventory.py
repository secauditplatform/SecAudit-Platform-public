from types import SimpleNamespace
from unittest.mock import MagicMock

from secaudit_core.audit_flow_inventory import (
    find_inventory_host,
    inventory_port_and_os,
    persist_audit_flow_hosts_to_inventory,
)


def _row(**kwargs):
    defaults = {
        "open_ports": None,
        "platform": None,
        "hostname": None,
        "ip_address": "192.168.1.10",
        "credential_id": None,
        "skip_reason": None,
        "ssh_known_hosts_entry": None,
        "ssh_host_key_fingerprint": None,
        "ephemeral_host_id": None,
        "ephemeral_credential_id": None,
        "id": 1,
    }
    defaults.update(kwargs)
    return SimpleNamespace(**defaults)


def test_inventory_port_and_os_windows_prefers_winrm():
    assert inventory_port_and_os(_row(platform="windows", open_ports="445,5985")) == (5985, "windows")


def test_inventory_port_and_os_linux_ssh():
    assert inventory_port_and_os(_row(platform="linux", open_ports="80,22")) == (22, "linux")


def test_inventory_port_and_os_network_device():
    assert inventory_port_and_os(_row(platform="network", open_ports="80,443")) == (80, "network")


def test_persist_skips_when_flag_off():
    run = SimpleNamespace(save_to_inventory=False, id=1)
    assert persist_audit_flow_hosts_to_inventory(MagicMock(), run) == 0


def test_persist_saves_host_without_credential():
    row = _row(credential_id=3, id=7)
    run = SimpleNamespace(save_to_inventory=True, id=1, owner_sub="alice")
    added: list[object] = []
    host_rows = MagicMock()
    host_rows.scalars.return_value = [row]
    empty = MagicMock()
    empty.scalars.return_value = []
    db = MagicMock()
    db.execute.side_effect = [host_rows, empty]

    def add(obj):
        added.append(obj)
        obj.id = 42

    db.add.side_effect = add
    saved = persist_audit_flow_hosts_to_inventory(db, run)
    assert saved == 1
    assert len(added) == 1
    assert added[0].credential_id is None
    assert added[0].is_ephemeral is False
    assert row.ephemeral_host_id == 42
    assert row.ephemeral_credential_id is None


def test_persist_does_not_attach_credential_to_existing_host():
    row = _row(credential_id=3, id=7)
    existing = SimpleNamespace(
        id=15,
        owner_sub="alice",
        os_type="linux",
        port=22,
        credential_id=None,
        ssh_known_hosts_entry=None,
    )
    run = SimpleNamespace(save_to_inventory=True, id=1, owner_sub="alice")
    host_rows = MagicMock()
    host_rows.scalars.return_value = [row]
    found = MagicMock()
    found.scalars.return_value = [existing]
    db = MagicMock()
    db.execute.side_effect = [host_rows, found]
    saved = persist_audit_flow_hosts_to_inventory(db, run)
    assert saved == 1
    db.add.assert_not_called()
    assert existing.credential_id is None
    assert row.ephemeral_host_id == 15
    assert row.ephemeral_credential_id is None


def test_find_inventory_host_prefers_same_owner():
    same = SimpleNamespace(owner_sub="alice", hostname="192.168.1.10", name="gw")
    other = SimpleNamespace(owner_sub=None, hostname="192.168.1.10", name="gw")
    result = MagicMock()
    result.scalars.return_value = [other, same]
    db = MagicMock()
    db.execute.return_value = result
    found = find_inventory_host(db, owner_sub="alice", ip="192.168.1.10", hostname=None)
    assert found is same
