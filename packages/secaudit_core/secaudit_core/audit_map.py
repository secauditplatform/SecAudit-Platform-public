"""Audit Map shaping: hosts already in inventory, check color, services, edges.

The map does not discover hosts, poll availability, or store sensors.
"""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime

NODE_CAP = 200
UNASSIGNED_SITE = "__none__"
NODE_STATUSES = ("pass", "fail", "error", "unchecked")
MAP_VIEWS = ("network", "service", "platform", "profile")

# Executors the platform already runs. Other ports have no matching check.
_PORT_EXECUTOR = {22: "ssh", 5985: "winrm", 5986: "winrm"}
_PORT_PROTOCOL = {22: "ssh", 80: "http", 443: "https", 5985: "winrm", 5986: "winrm"}


def protocol_for_port(port: int) -> str:
    return _PORT_PROTOCOL.get(int(port), "tcp")


def executor_for_port(port: int) -> str | None:
    return _PORT_EXECUTOR.get(int(port))


def parse_open_ports(raw: str | None) -> list[int]:
    if not raw or not str(raw).strip():
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(data, list):
        return []
    ports: list[int] = []
    for item in data:
        value: int | None = None
        if isinstance(item, bool):
            value = None
        elif isinstance(item, int):
            value = item
        elif isinstance(item, str) and item.isdigit():
            value = int(item)
        elif isinstance(item, dict) and "port" in item:
            try:
                value = int(item["port"])
            except (TypeError, ValueError):
                value = None
        if value is not None and 1 <= value <= 65535:
            ports.append(value)
    return sorted(set(ports))


def _is_ip(value: str | None) -> bool:
    if not value or not str(value).strip():
        return False
    try:
        ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    return True


def host_addresses(
    hostname: str | None,
    scan_ip: str | None = None,
    resolved: str | None = None,
) -> dict:
    """IP comes from the latest scan, otherwise from an address-shaped hostname.

    DNS is the scan's resolved name, otherwise a hostname that is not an IP.
    """
    ip = None
    dns = None
    if scan_ip and _is_ip(scan_ip):
        ip = str(scan_ip).strip()
    elif _is_ip(hostname):
        ip = str(hostname).strip()
    if resolved and str(resolved).strip() and not _is_ip(resolved):
        dns = str(resolved).strip()
    elif hostname and str(hostname).strip() and not _is_ip(hostname):
        dns = str(hostname).strip()
    return {"ip": ip, "dns": dns}


def ipv4_subnet(value: str | None) -> str | None:
    if not value:
        return None
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        return None
    if not isinstance(ip, ipaddress.IPv4Address):
        return None
    return str(ipaddress.ip_network(f"{ip}/24", strict=False))


def aggregate_status(statuses: list[str]) -> str:
    folded = {item for item in statuses if item in {"pass", "fail", "error", "skip", "pending"}}
    if "error" in folded:
        return "error"
    if "fail" in folded:
        return "fail"
    if "pass" in folded:
        return "pass"
    return "unchecked"


def host_card_status(statuses: list[str], *, run_failed: bool = False) -> str:
    """Card color is the outcome of the run, not the worst rule.

    FAIL only when the check produced no pass and ended in an error
    (a failed run, or rule status error). A finished run that has
    pass or fail results is PASS.
    """
    counts = _check_counts(statuses)
    ended_with_error = run_failed or counts["error"] > 0
    if ended_with_error and counts["pass"] == 0:
        return "fail"
    if counts["pass"] or counts["fail"] or counts["error"]:
        return "pass"
    if run_failed:
        return "fail"
    return "unchecked"


def _rank(finished_at: datetime | None, run_id: int) -> tuple[float, int]:
    stamp = finished_at.timestamp() if finished_at is not None else float("-inf")
    return (stamp, run_id)


def rollup_checks(rows: list[dict]) -> dict[int, dict]:
    """Latest completed run per host, and the latest run per executor on that host."""
    latest_run: dict[int, tuple[float, int]] = {}
    by_host_run: dict[tuple[int, int], list[str]] = {}
    run_failed: dict[tuple[int, int], bool] = {}
    run_profile: dict[tuple[int, int], tuple[int | None, str | None]] = {}
    latest_exec: dict[tuple[int, str], tuple[float, int]] = {}
    by_exec: dict[tuple[int, str, int], list[str]] = {}

    for row in rows:
        host_id = int(row["host_id"])
        run_id = int(row["job_run_id"])
        rank = _rank(row.get("finished_at"), run_id)
        status = str(row.get("status") or "").lower()
        previous = latest_run.get(host_id)
        if previous is None or rank > previous:
            latest_run[host_id] = rank
        by_host_run.setdefault((host_id, run_id), []).append(status)
        run_failed[(host_id, run_id)] = str(row.get("run_status") or "").lower() == "failed"
        raw_profile = row.get("profile_id")
        profile_name = row.get("profile_name")
        run_profile[(host_id, run_id)] = (
            int(raw_profile) if raw_profile is not None and profile_name else None,
            str(profile_name) if profile_name else None,
        )
        executor = row.get("execution_type")
        if executor:
            name = str(executor)
            key = (host_id, name)
            previous_exec = latest_exec.get(key)
            if previous_exec is None or rank > previous_exec:
                latest_exec[key] = rank
            by_exec.setdefault((host_id, name, run_id), []).append(status)

    result: dict[int, dict] = {}
    for host_id, rank in latest_run.items():
        run_id = rank[1]
        profile_id, profile_name = run_profile.get((host_id, run_id), (None, None))
        result[host_id] = {
            "status": host_card_status(
                by_host_run[(host_id, run_id)],
                run_failed=run_failed.get((host_id, run_id), False),
            ),
            "job_run_id": run_id,
            "profile_id": profile_id,
            "profile_name": profile_name,
            "by_executor": {},
            "checks": _check_counts(by_host_run[(host_id, run_id)]),
        }
    for (host_id, executor), rank in latest_exec.items():
        run_id = rank[1]
        result.setdefault(
            host_id, {"status": "unchecked", "job_run_id": None, "by_executor": {}}
        )
        result[host_id]["by_executor"][executor] = aggregate_status(by_exec[(host_id, executor, run_id)])
    return result


def rollup_profiles(rows: list[dict]) -> dict[int, list[dict]]:
    """Latest terminal run of each profile on a host. Rows without a profile are skipped."""
    latest: dict[tuple[int, int], tuple[float, int]] = {}
    by_run: dict[tuple[int, int], list[str]] = {}
    run_failed: dict[tuple[int, int], bool] = {}
    names: dict[int, str] = {}

    for row in rows:
        raw_id = row.get("profile_id")
        if raw_id is None:
            continue
        profile_id = int(raw_id)
        host_id = int(row["host_id"])
        run_id = int(row["job_run_id"])
        rank = _rank(row.get("finished_at"), run_id)
        names[profile_id] = str(row.get("profile_name") or profile_id)
        key = (host_id, profile_id)
        previous = latest.get(key)
        if previous is None or rank > previous:
            latest[key] = rank
        by_run.setdefault((host_id, run_id), []).append(str(row.get("status") or "").lower())
        run_failed[(host_id, run_id)] = str(row.get("run_status") or "").lower() == "failed"

    grouped: dict[int, list[dict]] = {}
    for (host_id, profile_id), rank in latest.items():
        run_id = rank[1]
        statuses = by_run.get((host_id, run_id), [])
        grouped.setdefault(host_id, []).append(
            {
                "id": profile_id,
                "name": names.get(profile_id) or str(profile_id),
                "status": host_card_status(
                    statuses,
                    run_failed=run_failed.get((host_id, run_id), False),
                ),
                "job_run_id": run_id,
                "checks": _check_counts(statuses),
            }
        )
    for items in grouped.values():
        items.sort(key=lambda item: (str(item["name"]).casefold(), item["id"]))
    return grouped


def _check_counts(statuses: list[str]) -> dict[str, int]:
    counts = {"pass": 0, "fail": 0, "error": 0}
    for status in statuses:
        if status in counts:
            counts[status] += 1
    return counts


def choose_site(requested: str | None, sites: list[str]) -> str | None:
    """Without a site filter the map opens the unassigned site."""
    if requested == UNASSIGNED_SITE:
        return None
    if requested:
        return requested
    return None


def coverage_reason(port: int, catalog_executors: set[str], service_status: str) -> str | None:
    executor = executor_for_port(port)
    if executor is None or executor not in catalog_executors:
        return "no_profile"
    if service_status == "unchecked":
        return "unchecked"
    return None


def build_edge(source_host_id: int, source_port: int, target_host_id: int, target_port: int) -> dict:
    """A check-together link names two existing services. It does not allocate a host."""
    if source_host_id == target_host_id and source_port == target_port:
        raise ValueError("same service")
    if source_host_id > target_host_id or (
        source_host_id == target_host_id and source_port > target_port
    ):
        source_host_id, target_host_id = target_host_id, source_host_id
        source_port, target_port = target_port, source_port
    return {
        "source_host_id": source_host_id,
        "source_port": source_port,
        "target_host_id": target_host_id,
        "target_port": target_port,
    }


def group_nodes(nodes: list[dict], view: str) -> list[dict]:
    """Same hosts, four pictures. Ports and profiles may repeat a host."""
    chosen = view if view in MAP_VIEWS else "network"
    buckets: dict[str | None, list[dict]] = {}
    order: list[str | None] = []

    def add(key: str | None, node: dict) -> None:
        if key not in buckets:
            buckets[key] = []
            order.append(key)
        buckets[key].append(node)

    for node in nodes:
        if chosen == "service":
            services = node.get("services") or []
            if not services:
                add(None, node)
                continue
            for service in services:
                add(f"{service['port']}/{service['protocol']}", node)
        elif chosen == "platform":
            name = str(node.get("os_type") or "").strip().lower() or "other"
            add(name, node)
        elif chosen == "profile":
            profiles = [item for item in (node.get("profiles") or []) if item.get("name")]
            if not profiles:
                add(None, node)
                continue
            for profile in profiles:
                placed = dict(node)
                placed["status"] = profile["status"]
                placed["last_job_run_id"] = profile.get("job_run_id")
                placed["checks"] = profile.get("checks")
                placed["profile_id"] = profile.get("id")
                placed["profile_name"] = profile.get("name")
                add(str(profile["name"]), placed)
        else:
            add(node.get("subnet"), node)

    grouped = [
        {
            "key": key,
            "status": aggregate_status([item.get("status") or "unchecked" for item in buckets[key]]),
            "nodes": buckets[key],
        }
        for key in order
    ]
    if chosen == "profile":
        grouped.sort(key=lambda item: (item["key"] is None, str(item["key"] or "").casefold()))
    return grouped


def job_hosts_param(host_ids: list[int]) -> str:
    seen: dict[int, None] = {}
    for host_id in host_ids:
        if isinstance(host_id, int) and host_id > 0:
            seen.setdefault(host_id, None)
    return ",".join(str(host_id) for host_id in seen)


def audit_flow_targets(addresses: list[str]) -> str:
    seen: dict[str, None] = {}
    for address in addresses:
        text = (address or "").strip()
        if text:
            seen.setdefault(text, None)
    return ",".join(seen)


def _service_row(
    host: dict,
    port: int,
    *,
    source: str,
    confirmed: bool,
    service_id: int | None,
    rollup: dict,
    catalog: set[str],
) -> dict:
    host_roll = rollup.get(host["id"], {})
    executor = executor_for_port(port)
    if executor:
        status = host_roll.get("by_executor", {}).get(executor, "unchecked")
    else:
        status = "unchecked"
    return {
        "id": service_id,
        "port": port,
        "protocol": protocol_for_port(port),
        "source": source,
        "confirmed": confirmed,
        "status": status,
        "coverage_reason": coverage_reason(port, catalog, status),
    }


def assemble_map(
    hosts: list[dict],
    *,
    requested_site: str | None,
    positions: dict[int, tuple[float, float]],
    scan_ports: dict[int, list[int]],
    manual_services: list[dict],
    check_rows: list[dict],
    catalog_executors: set[str],
    edges: list[dict],
) -> dict:
    sites = sorted({host["site"] for host in hosts if host.get("site")})
    has_unassigned = any(not host.get("site") for host in hosts)
    site = choose_site(requested_site, sites)
    visible = [host for host in hosts if (host.get("site") or None) == site]
    visible.sort(key=lambda host: (host.get("name") or "", host["id"]))
    truncated = len(visible) > NODE_CAP
    visible = visible[:NODE_CAP]
    visible_ids = {host["id"] for host in visible}
    rollup = rollup_checks(check_rows)
    profile_roll = rollup_profiles(check_rows)
    manual_by_host: dict[int, dict[int, int]] = {}
    for item in manual_services:
        if item["host_id"] in visible_ids:
            manual_by_host.setdefault(item["host_id"], {})[int(item["port"])] = int(item["id"])

    nodes: list[dict] = []
    for host in visible:
        host_id = host["id"]
        host_roll = rollup.get(host_id, {})
        addresses = host_addresses(
            host.get("hostname"),
            host.get("scan_ip"),
            host.get("resolved_hostname"),
        )
        services: dict[int, dict] = {}
        connection = int(host.get("port") or 22)
        services[connection] = _service_row(
            host,
            connection,
            source="connection",
            confirmed=True,
            service_id=manual_by_host.get(host_id, {}).get(connection),
            rollup=rollup,
            catalog=catalog_executors,
        )
        for port in scan_ports.get(host_id, []):
            if port in services:
                continue
            confirmed_id = manual_by_host.get(host_id, {}).get(port)
            services[port] = _service_row(
                host,
                port,
                source="scan",
                confirmed=confirmed_id is not None,
                service_id=confirmed_id,
                rollup=rollup,
                catalog=catalog_executors,
            )
        for port, service_id in manual_by_host.get(host_id, {}).items():
            if port in services:
                services[port]["confirmed"] = True
                services[port]["id"] = service_id
                continue
            services[port] = _service_row(
                host,
                port,
                source="manual",
                confirmed=True,
                service_id=service_id,
                rollup=rollup,
                catalog=catalog_executors,
            )
        xy = positions.get(host_id)
        nodes.append(
            {
                "host_id": host_id,
                "name": host.get("name") or "",
                "hostname": host.get("hostname") or "",
                "ip": addresses["ip"],
                "dns": addresses["dns"],
                "port": connection,
                "os_type": host.get("os_type"),
                "site": host.get("site"),
                "environment": host.get("environment"),
                "criticality": host.get("criticality"),
                "tags": list(host.get("tags") or []),
                "status": host_roll.get("status", "unchecked"),
                "last_job_run_id": host_roll.get("job_run_id"),
                "checks": host_roll.get("checks"),
                "profile_id": host_roll.get("profile_id"),
                "profile_name": host_roll.get("profile_name"),
                "x": xy[0] if xy else None,
                "y": xy[1] if xy else None,
                "subnet": ipv4_subnet(addresses["ip"] or host.get("hostname")),
                "services": [services[port] for port in sorted(services)],
                "profiles": profile_roll.get(host_id, []),
            }
        )

    groups: dict[str | None, list] = {}
    for node in nodes:
        groups.setdefault(node["subnet"], []).append(node)

    visible_edges = [
        edge
        for edge in edges
        if edge["source_host_id"] in visible_ids and edge["target_host_id"] in visible_ids
    ]
    grouped = [{"subnet": subnet, "nodes": group_nodes_list} for subnet, group_nodes_list in groups.items()]
    flat = [node for group in grouped for node in group["nodes"]]
    return {
        "site": site,
        "sites": sites,
        "has_unassigned": has_unassigned,
        "truncated": truncated,
        "groups": grouped,
        "views": {name: group_nodes(flat, name) for name in MAP_VIEWS},
        "edges": visible_edges,
    }


def coverage_items(map_payload: dict) -> list[dict]:
    rows: list[dict] = []
    for group in map_payload["groups"]:
        for node in group["nodes"]:
            for service in node["services"]:
                reason = service["coverage_reason"]
                if not reason:
                    continue
                rows.append(
                    {
                        "host_id": node["host_id"],
                        "name": node["name"],
                        "hostname": node["hostname"],
                        "site": node["site"],
                        "port": service["port"],
                        "protocol": service["protocol"],
                        "source": service["source"],
                        "confirmed": service["confirmed"],
                        "reason": reason,
                    }
                )
    return rows
