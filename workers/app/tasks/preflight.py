"""Celery tasks for host/credential pre-flight probes."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import selectinload, sessionmaker

from app.celery_app import celery_app, settings
from app.preflight_probe import probe_host_record
from secaudit_core.audit_map import parse_open_ports
from secaudit_core.hosts import load_active_hosts, resolve_job_targets
from secaudit_core.models import InventoryScanResult, Job, Playbook, Profile, ProfileVersion
from secaudit_core.preflight import profile_fit, profile_platform
from secaudit_core.profile_packages import count_profile_rules_metadata

engine = create_engine(settings.database_url_sync)
SessionLocal = sessionmaker(bind=engine)


@celery_app.task(name="app.tasks.preflight.probe_host", soft_time_limit=30, time_limit=40)
def probe_host(host_id: int, credential_id: int | None = None) -> dict:
    with SessionLocal() as db:
        return probe_host_record(db, host_id, credential_id, settings)


def _profile_for_job(db, job: Job) -> Profile | None:
    profile_id = job.profile_id
    if profile_id is None and job.playbook_id:
        playbook = db.get(Playbook, job.playbook_id)
        profile_id = playbook.profile_id if playbook is not None else None
    if profile_id is None:
        return None
    return db.execute(
        select(Profile).options(selectinload(Profile.category)).where(Profile.id == profile_id)
    ).scalar_one_or_none()


def _rules_count(db, job: Job, profile: Profile) -> int:
    version_id = job.profile_version_id
    if version_id is not None:
        version = db.get(ProfileVersion, version_id)
        if version is not None and version.profile_id == profile.id:
            return len(version.requirement_ids or [])
    if profile.package_path:
        package_dir = Path(profile.package_path)
        if package_dir.is_dir():
            return count_profile_rules_metadata(package_dir)
    return 0


def _applicability(db, job: Job, hosts) -> dict | None:
    profile = _profile_for_job(db, job)
    if profile is None:
        return None
    category = profile.category
    plat = profile_platform(
        os_name=profile.os_name,
        category_name=category.name if category else None,
        category_slug=getattr(category, "slug", None) if category else None,
    )
    slug = getattr(category, "slug", None) if category else None
    ports = _latest_open_ports(db, [host.id for host in hosts]) if (slug or "").lower() == "services" else {}
    rows = []
    applicable = 0
    for host in hosts:
        verdict = profile_fit(
            host_os_type=host.os_type,
            host_os_family=host.os_family,
            host_os_version=host.os_version,
            profile_os_name=profile.os_name,
            profile_os_version=profile.os_version,
            profile_name=profile.profile_name,
            profile_plat=plat,
            category_slug=slug,
            open_ports=ports.get(host.id),
        )
        if verdict == "match":
            applicable += 1
        rows.append(
            {
                "host_id": host.id,
                "host_name": host.name or host.hostname,
                "os_type": host.os_type,
                "applicable": verdict == "match",
                "reason": verdict,
            }
        )
    total = len(rows)
    return {
        "profile_id": profile.id,
        "profile_name": profile.profile_name,
        "profile_platform": plat,
        "rules_count": _rules_count(db, job, profile),
        "hosts_total": total,
        "hosts_applicable": applicable,
        "hosts_inapplicable": total - applicable,
        "hosts": rows,
    }


def _latest_open_ports(db, host_ids: list[int]) -> dict[int, list[int]]:
    if not host_ids:
        return {}
    rows = db.execute(
        select(InventoryScanResult.host_id, InventoryScanResult.open_ports)
        .where(InventoryScanResult.host_id.in_(host_ids))
        .distinct(InventoryScanResult.host_id)
        .order_by(
            InventoryScanResult.host_id,
            InventoryScanResult.created_at.desc(),
            InventoryScanResult.id.desc(),
        )
    )
    return {host_id: parse_open_ports(raw) for host_id, raw in rows if host_id is not None}


def _probe_one(host_id: int) -> dict:
    try:
        with SessionLocal() as db:
            return probe_host_record(db, host_id, None, settings)
    except Exception as exc:
        return {
            "ok": False,
            "target": str(host_id),
            "checks": [],
            "duration_ms": 0,
            "error": str(exc)[:300],
        }


@celery_app.task(name="app.tasks.preflight.probe_job")
def probe_job(job_id: int) -> dict:
    with SessionLocal() as db:
        job = db.get(Job, job_id)
        if job is None:
            return {"error": "Job not found", "probes": [], "applicability": None}
        host_ids = resolve_job_targets(
            db,
            job.id,
            job.dynamic_filter,
            owner_sub=job.owner_sub,
            enforce_owner_scope=job.enforce_host_owner_scope,
        )
        hosts = load_active_hosts(db, host_ids)
        applicability = _applicability(db, job, hosts)
        active_ids = [host.id for host in hosts]
    if not active_ids:
        return {"error": "No active hosts assigned to job", "probes": [], "applicability": applicability}
    workers = min(8, len(active_ids))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        probes = list(pool.map(_probe_one, active_ids))
    return {"error": None, "probes": probes, "applicability": applicability}
