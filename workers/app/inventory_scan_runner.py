"""Sync inventory scan execution (Celery worker)."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import create_engine, func, or_, select
from sqlalchemy.orm import Session, sessionmaker

from secaudit_core.inventory_scan import (
    NMAP_PORT_SCAN_ARGS,
    ScanCancelledError,
    decode_nmap_flags,
    host_name_for_ip,
    infer_host_defaults,
    parse_nmap_discovery_xml,
    parse_nmap_port_scan_xml,
)
from secaudit_core.inventory_scan_state import (
    clear_scan_pid,
    clear_scan_state,
    is_scan_cancelled,
    set_scan_pid,
)
from secaudit_core.models import Host, InventoryScan, InventoryScanResult, JobStatus
from secaudit_core.run_state import claim_pending_run, transition_running_run

# Small chunks so the UI sees hosts/ports after each batch instead of only at the end.
PORT_SCAN_CHUNK_SIZE = 8


def _is_scan_active(db: Session, scan_id: int) -> bool:
    scan = db.get(InventoryScan, scan_id)
    return scan is not None and scan.status == JobStatus.RUNNING


def _run_nmap_sync(
    args: list[str],
    scan_id: int,
    redis_url: str,
    *,
    poll_interval: float = 0.5,
) -> tuple[str, str]:
    """Run nmap and return (xml_text, stderr).

    Both XML and stderr are written to temp files. Using PIPE for either stream
    deadlocks once the OS pipe buffer fills (common on /24 discovery/port scans
    when nmap emits progress on stderr).
    """
    if is_scan_cancelled(redis_url, scan_id):
        raise ScanCancelledError()

    xml_path: str | None = None
    stderr_path: str | None = None
    stderr_handle = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=f"secaudit-nmap-{scan_id}-",
            suffix=".xml",
            delete=False,
        ) as handle:
            xml_path = handle.name

        stderr_handle = tempfile.NamedTemporaryFile(
            prefix=f"secaudit-nmap-{scan_id}-",
            suffix=".err",
            delete=False,
            mode="w+b",
        )
        stderr_path = stderr_handle.name

        proc = subprocess.Popen(
            ["nmap", *args, "-oX", xml_path],
            stdout=subprocess.DEVNULL,
            stderr=stderr_handle,
        )
        set_scan_pid(redis_url, scan_id, proc.pid)
        try:
            while proc.poll() is None:
                if is_scan_cancelled(redis_url, scan_id):
                    proc.terminate()
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
                    raise ScanCancelledError()
                time.sleep(poll_interval)

            returncode = proc.wait()
            stderr_handle.flush()
            stderr = Path(stderr_path).read_text(encoding="utf-8", errors="replace")
            xml_text = Path(xml_path).read_text(encoding="utf-8", errors="replace")
            if returncode not in (0,) and not xml_text.strip():
                raise RuntimeError(stderr.strip() or f"nmap exited with code {returncode}")
            return xml_text, stderr
        finally:
            clear_scan_pid(redis_url, scan_id)
    finally:
        if stderr_handle is not None:
            try:
                stderr_handle.close()
            except OSError:
                pass
        for path in (xml_path, stderr_path):
            if path:
                try:
                    os.unlink(path)
                except OSError:
                    pass


def _persist_discovered_hosts(
    db: Session,
    scan: InventoryScan,
    discovered: list[dict],
) -> None:
    """Write discovery hits immediately so the UI can show hosts before port scan finishes."""
    existing = {
        row.ip_address
        for row in db.execute(
            select(InventoryScanResult).where(InventoryScanResult.scan_id == scan.id)
        ).scalars()
    }
    for entry in discovered:
        ip = entry["ip"]
        if ip in existing:
            continue
        db.add(
            InventoryScanResult(
                scan_id=scan.id,
                ip_address=ip,
                resolved_hostname=entry.get("hostname"),
                host_id=None,
                open_ports=None,
                is_active=False,
            )
        )
    scan.hosts_found = len(discovered)
    db.commit()


def _identity_keys(ip: str, resolved_hostname: str | None) -> list[str]:
    """Normalized identity keys used to detect an already-known host."""
    keys: list[str] = []
    for raw in (ip, resolved_hostname):
        if not raw:
            continue
        value = raw.strip()
        if not value:
            continue
        lowered = value.lower()
        if lowered not in keys:
            keys.append(lowered)
    return keys


def _find_existing_host(
    db: Session,
    *,
    owner_sub: str | None,
    ip: str,
    resolved_hostname: str | None,
) -> Host | None:
    """Find a reusable host for this scan owner (or legacy unowned host).

    Matches by IP or resolved DNS against Host.hostname / Host.name so rescans
    do not create duplicates when the inventory already contains the target.
    Other owners' hosts are never linked (object RBAC isolation).
    """
    keys = _identity_keys(ip, resolved_hostname)
    if not keys:
        return None

    identity_match = or_(
        func.lower(Host.hostname).in_(keys),
        func.lower(Host.name).in_(keys),
    )
    if owner_sub is None:
        owner_match = Host.owner_sub.is_(None)
    else:
        owner_match = or_(Host.owner_sub == owner_sub, Host.owner_sub.is_(None))

    candidates = list(
        db.execute(select(Host).where(identity_match, owner_match).limit(20)).scalars()
    )
    if not candidates:
        return None

    same_owner = [host for host in candidates if host.owner_sub == owner_sub]
    if same_owner:
        return same_owner[0]
    return candidates[0]


def _apply_port_info_chunk(
    db: Session,
    scan: InventoryScan,
    chunk_ips: list[str],
    port_info_by_ip: dict,
) -> int:
    """Update result rows for a port-scan chunk and create Host rows for open ports.

    Already-known hosts (same owner / legacy unowned) are linked and not re-created.
    """
    rows = list(
        db.execute(
            select(InventoryScanResult).where(
                InventoryScanResult.scan_id == scan.id,
                InventoryScanResult.ip_address.in_(chunk_ips),
            )
        ).scalars()
    )
    by_ip = {row.ip_address: row for row in rows}
    hosts_created = 0

    for ip in chunk_ips:
        row = by_ip.get(ip)
        if row is None:
            continue
        port_entry = port_info_by_ip.get(ip)
        if port_entry and port_entry.get("hostname"):
            row.resolved_hostname = port_entry["hostname"]
        open_ports = port_entry["open_ports"] if port_entry else []
        row.open_ports = json.dumps(open_ports)
        row.is_active = bool(open_ports)

        if not open_ports:
            continue
        if row.host_id is not None:
            continue

        existing = _find_existing_host(
            db,
            owner_sub=scan.owner_sub,
            ip=ip,
            resolved_hostname=row.resolved_hostname,
        )
        if existing:
            # Claim legacy unowned hosts for the scan initiator.
            if existing.owner_sub is None and scan.owner_sub is not None:
                existing.owner_sub = scan.owner_sub
            row.host_id = existing.id
            continue

        default_port, os_type = infer_host_defaults(open_ports)
        created = Host(
            name=host_name_for_ip(ip, row.resolved_hostname),
            hostname=ip,
            port=default_port,
            os_type=os_type,
            is_active=True,
            owner_sub=scan.owner_sub,
        )
        db.add(created)
        db.flush()
        hosts_created += 1
        row.host_id = created.id

    scan.hosts_created = (scan.hosts_created or 0) + hosts_created
    db.commit()
    return hosts_created


def run_inventory_scan_sync(scan_id: int, *, database_url: str, redis_url: str) -> None:
    """Execute inventory scan synchronously (called from Celery worker)."""
    engine = create_engine(database_url)
    SessionLocal = sessionmaker(bind=engine)

    with SessionLocal() as db:
        if not claim_pending_run(db, InventoryScan, scan_id):
            return
        scan = db.get(InventoryScan, scan_id)
        target = scan.target
        nmap_flags = scan.nmap_flags

    try:
        flags_data = decode_nmap_flags(nmap_flags)

        if flags_data.get("mode") == "custom":
            custom_args = flags_data.get("flags", [])
            scan_out, scan_err = _run_nmap_sync([*custom_args, target], scan_id, redis_url)
            with SessionLocal() as db:
                if not _is_scan_active(db, scan_id):
                    return
            if not scan_out.strip():
                raise RuntimeError(scan_err.strip() or "nmap scan produced no output")
            discovered = parse_nmap_discovery_xml(scan_out)
            port_info_by_ip = parse_nmap_port_scan_xml(scan_out)
            if not discovered and port_info_by_ip:
                discovered = [
                    {"ip": info["ip"], "hostname": info["hostname"]}
                    for info in port_info_by_ip.values()
                ]
            with SessionLocal() as db:
                scan = db.get(InventoryScan, scan_id)
                if not scan or scan.status == JobStatus.CANCELLED:
                    return
                _persist_discovered_hosts(db, scan, discovered)
                if discovered:
                    _apply_port_info_chunk(
                        db,
                        scan,
                        [entry["ip"] for entry in discovered],
                        port_info_by_ip,
                    )
                transition_running_run(
                    db, InventoryScan, scan_id, JobStatus.COMPLETED
                )
            return

        discovery_args = flags_data.get("discovery", ["-sn"])
        port_scan_args = flags_data.get("port_scan", list(NMAP_PORT_SCAN_ARGS))

        discovery_out, discovery_err = _run_nmap_sync(
            [*discovery_args, target], scan_id, redis_url
        )
        with SessionLocal() as db:
            if not _is_scan_active(db, scan_id):
                return
        if not discovery_out.strip():
            raise RuntimeError(discovery_err.strip() or "nmap discovery produced no output")

        discovered = parse_nmap_discovery_xml(discovery_out)

        with SessionLocal() as db:
            scan = db.get(InventoryScan, scan_id)
            if not scan or scan.status == JobStatus.CANCELLED:
                return
            _persist_discovered_hosts(db, scan, discovered)

        if discovered:
            port_targets = [entry["ip"] for entry in discovered]
            for offset in range(0, len(port_targets), PORT_SCAN_CHUNK_SIZE):
                chunk = port_targets[offset : offset + PORT_SCAN_CHUNK_SIZE]
                port_out, port_err = _run_nmap_sync(
                    [*port_scan_args, *chunk],
                    scan_id,
                    redis_url,
                )
                with SessionLocal() as db:
                    if not _is_scan_active(db, scan_id):
                        return
                if not port_out.strip():
                    raise RuntimeError(port_err.strip() or "nmap port scan produced no output")
                chunk_ports = parse_nmap_port_scan_xml(port_out)
                with SessionLocal() as db:
                    scan = db.get(InventoryScan, scan_id)
                    if not scan or scan.status == JobStatus.CANCELLED:
                        return
                    _apply_port_info_chunk(db, scan, chunk, chunk_ports)

        with SessionLocal() as db:
            scan = db.get(InventoryScan, scan_id)
            if not scan or scan.status == JobStatus.CANCELLED:
                return
            transition_running_run(db, InventoryScan, scan_id, JobStatus.COMPLETED)
    except ScanCancelledError:
        with SessionLocal() as db:
            scan = db.get(InventoryScan, scan_id)
            if scan:
                transition_running_run(
                    db,
                    InventoryScan,
                    scan_id,
                    JobStatus.CANCELLED,
                    error_message="Cancelled by user",
                )
    except Exception as exc:
        with SessionLocal() as db:
            scan = db.get(InventoryScan, scan_id)
            if not scan:
                return
            transition_running_run(
                db,
                InventoryScan,
                scan_id,
                JobStatus.FAILED,
                error_message=str(exc),
            )
    finally:
        clear_scan_state(redis_url, scan_id)
