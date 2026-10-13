"""Load inventory hosts into an Audit Map. Does not create hosts."""

from __future__ import annotations

from fastapi import HTTPException
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased, selectinload

from app.core.auth import AuthUser
from app.models import (
    AuditMapEdge,
    AuditMapService,
    CheckResult,
    CheckScript,
    Host,
    HostTag,
    HostTagLink,
    InventoryScan,
    InventoryScanResult,
    Job,
    JobHost,
    JobRun,
    JobStatus,
    Playbook,
    Profile,
    ScriptKind,
)
from app.services.object_rbac import apply_owner_scope, assert_can_access
from secaudit_core.audit_map import UNASSIGNED_SITE, assemble_map, build_edge, parse_open_ports


async def _visible_hosts(
    db: AsyncSession,
    user: AuthUser,
    *,
    environment: str | None,
    criticality: str | None,
    tag: str | None,
) -> list[Host]:
    stmt = select(Host).options(selectinload(Host.tags).selectinload(HostTagLink.tag))
    stmt = apply_owner_scope(stmt, Host.owner_sub, user)
    stmt = stmt.where(Host.is_ephemeral.is_(False))
    if environment and environment.strip():
        stmt = stmt.where(Host.environment == environment.strip())
    if criticality and criticality.strip():
        stmt = stmt.where(Host.criticality == criticality.strip().lower())
    if tag and tag.strip():
        tag_stmt = (
            select(HostTagLink.host_id)
            .join(HostTag, HostTag.id == HostTagLink.tag_id)
            .where(HostTag.name == tag.strip())
        )
        stmt = stmt.where(Host.id.in_(tag_stmt))
    stmt = stmt.order_by(Host.name, Host.id)
    result = await db.execute(stmt)
    return list(result.scalars().unique().all())


def _host_dict(host: Host) -> dict:
    return {
        "id": host.id,
        "name": host.name,
        "hostname": host.hostname,
        "port": host.port,
        "os_type": host.os_type,
        "site": host.site,
        "environment": host.environment,
        "criticality": host.criticality,
        "tags": sorted(link.tag.name for link in host.tags if link.tag),
    }


async def _require_host(db: AsyncSession, user: AuthUser, host_id: int) -> Host:
    host = await db.get(Host, host_id)
    if host is None or host.is_ephemeral:
        raise HTTPException(status_code=404, detail="Host not found")
    assert_can_access(user, host.owner_sub, detail="Host not found")
    return host


async def _hosts_for_profile(db: AsyncSession, profile_id: int) -> set[int]:
    direct = await db.execute(
        select(JobHost.host_id).join(Job, Job.id == JobHost.job_id).where(Job.profile_id == profile_id)
    )
    via_playbook = await db.execute(
        select(JobHost.host_id)
        .join(Job, Job.id == JobHost.job_id)
        .join(Playbook, Playbook.id == Job.playbook_id)
        .where(Playbook.profile_id == profile_id)
    )
    return set(direct.scalars()) | set(via_playbook.scalars())


async def build_audit_map(
    db: AsyncSession,
    user: AuthUser,
    *,
    site: str | None,
    environment: str | None,
    criticality: str | None,
    tag: str | None,
    profile: str | None = None,
) -> dict:
    hosts = await _visible_hosts(
        db, user, environment=environment, criticality=criticality, tag=tag
    )
    profile_id = int(profile) if profile and profile.isdigit() else None
    if profile_id is not None:
        allowed = await _hosts_for_profile(db, profile_id)
        hosts = [host for host in hosts if host.id in allowed]
    host_ids = [host.id for host in hosts]
    positions: dict[int, tuple[float, float]] = {}
    addresses: dict[int, tuple[str | None, str | None]] = {}
    scan_ports: dict[int, list[int]] = {}
    manual: list[dict] = []
    check_rows: list[dict] = []
    edges: list[dict] = []
    catalog: set[str] = set()

    if host_ids:
        scan_rows = await db.execute(
            select(InventoryScanResult, InventoryScan.finished_at, InventoryScan.id)
            .join(InventoryScan, InventoryScan.id == InventoryScanResult.scan_id)
            .where(
                InventoryScanResult.host_id.in_(host_ids),
                InventoryScan.status == JobStatus.COMPLETED,
            )
        )
        latest_scan: dict[int, tuple] = {}
        for result_row, finished_at, scan_id in scan_rows.all():
            if result_row.host_id is None:
                continue
            rank = (finished_at is not None, finished_at or scan_id, scan_id)
            previous = latest_scan.get(result_row.host_id)
            if previous is None or rank > previous[0]:
                latest_scan[result_row.host_id] = (rank, result_row)
        for host_id, (_, result_row) in latest_scan.items():
            scan_ports[host_id] = parse_open_ports(result_row.open_ports)
            addresses[host_id] = (result_row.ip_address, result_row.resolved_hostname)

        service_rows = await db.execute(
            select(AuditMapService).where(AuditMapService.host_id.in_(host_ids))
        )
        manual = [{"id": row.id, "host_id": row.host_id, "port": row.port} for row in service_rows.scalars()]

        job_profile = aliased(Profile)
        playbook_profile = aliased(Profile)
        check_stmt = (
            select(
                CheckResult.host_id,
                CheckResult.status,
                CheckResult.job_run_id,
                JobRun.finished_at,
                JobRun.status,
                Job.execution_type,
                Job.profile_id.label("job_profile_id"),
                Playbook.profile_id.label("playbook_profile_id"),
                job_profile.profile_name.label("job_profile_name"),
                playbook_profile.profile_name.label("playbook_profile_name"),
            )
            .join(JobRun, JobRun.id == CheckResult.job_run_id)
            .join(Job, Job.id == JobRun.job_id)
            .outerjoin(Playbook, Playbook.id == Job.playbook_id)
            .outerjoin(job_profile, job_profile.id == Job.profile_id)
            .outerjoin(playbook_profile, playbook_profile.id == Playbook.profile_id)
            .where(
                CheckResult.host_id.in_(host_ids),
                JobRun.status.in_([JobStatus.COMPLETED, JobStatus.FAILED]),
            )
        )
        if profile_id is not None:
            check_stmt = check_stmt.where(
                or_(Job.profile_id == profile_id, Playbook.profile_id == profile_id)
            )
        check_result = await db.execute(check_stmt)
        for (
            host_id,
            status,
            job_run_id,
            finished_at,
            run_status,
            execution_type,
            job_profile_id,
            playbook_profile_id,
            job_profile_name,
            playbook_profile_name,
        ) in check_result.all():
            check_rows.append(
                {
                    "host_id": host_id,
                    "status": status.value if hasattr(status, "value") else str(status),
                    "job_run_id": job_run_id,
                    "finished_at": finished_at,
                    "run_status": run_status.value if hasattr(run_status, "value") else str(run_status),
                    "execution_type": execution_type.value if hasattr(execution_type, "value") else execution_type,
                    "profile_id": job_profile_id or playbook_profile_id,
                    "profile_name": job_profile_name or playbook_profile_name,
                }
            )

        edge_rows = await db.execute(
            select(AuditMapEdge).where(
                AuditMapEdge.source_host_id.in_(host_ids),
                AuditMapEdge.target_host_id.in_(host_ids),
            )
        )
        edges = [
            {
                "id": row.id,
                "source_host_id": row.source_host_id,
                "source_port": row.source_port,
                "target_host_id": row.target_host_id,
                "target_port": row.target_port,
            }
            for row in edge_rows.scalars()
        ]

    catalog_rows = await db.execute(
        select(CheckScript.execution_type).where(CheckScript.script_kind == ScriptKind.AUDIT).distinct()
    )
    for execution_type in catalog_rows.scalars():
        catalog.add(execution_type.value if hasattr(execution_type, "value") else str(execution_type))

    requested = site.strip() if site else None
    if requested == "":
        requested = None
    host_rows = []
    for host in hosts:
        item = _host_dict(host)
        scan_ip, resolved = addresses.get(host.id, (None, None))
        item["scan_ip"] = scan_ip
        item["resolved_hostname"] = resolved
        host_rows.append(item)
    payload = assemble_map(
        host_rows,
        requested_site=requested,
        positions=positions,
        scan_ports=scan_ports,
        manual_services=manual,
        check_rows=check_rows,
        catalog_executors=catalog,
        edges=edges,
    )
    profile_rows = await db.execute(
        select(Profile.id, Profile.profile_name)
        .where(Profile.is_active.is_(True))
        .order_by(Profile.profile_name)
    )
    payload["profiles"] = [{"id": row_id, "name": name} for row_id, name in profile_rows.all()]
    return payload


async def confirm_service(db: AsyncSession, user: AuthUser, host_id: int, port: int) -> AuditMapService:
    host = await _require_host(db, user, host_id)
    existing = await db.execute(
        select(AuditMapService).where(AuditMapService.host_id == host.id, AuditMapService.port == port)
    )
    row = existing.scalar_one_or_none()
    if row is None:
        row = AuditMapService(host_id=host.id, port=port)
        db.add(row)
        await db.commit()
        await db.refresh(row)
    return row


async def delete_service(db: AsyncSession, user: AuthUser, service_id: int) -> None:
    row = await db.get(AuditMapService, service_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Service not found")
    await _require_host(db, user, row.host_id)
    await db.delete(row)
    await db.commit()


async def create_edge(db: AsyncSession, user: AuthUser, payload: dict) -> AuditMapEdge:
    await _require_host(db, user, int(payload["source_host_id"]))
    await _require_host(db, user, int(payload["target_host_id"]))
    try:
        normalized = build_edge(
            int(payload["source_host_id"]),
            int(payload["source_port"]),
            int(payload["target_host_id"]),
            int(payload["target_port"]),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Choose two different services") from exc
    existing = await db.execute(
        select(AuditMapEdge).where(
            AuditMapEdge.source_host_id == normalized["source_host_id"],
            AuditMapEdge.source_port == normalized["source_port"],
            AuditMapEdge.target_host_id == normalized["target_host_id"],
            AuditMapEdge.target_port == normalized["target_port"],
        )
    )
    row = existing.scalar_one_or_none()
    if row is None:
        row = AuditMapEdge(created_by=user.sub, **normalized)
        db.add(row)
        await db.commit()
        await db.refresh(row)
    return row


async def delete_edge(db: AsyncSession, user: AuthUser, edge_id: int) -> None:
    row = await db.get(AuditMapEdge, edge_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Link not found")
    await _require_host(db, user, row.source_host_id)
    await _require_host(db, user, row.target_host_id)
    await db.delete(row)
    await db.commit()


def site_query(site: str | None) -> str | None:
    if site is None:
        return None
    text = site.strip()
    if not text:
        return None
    return text if text != UNASSIGNED_SITE else UNASSIGNED_SITE
