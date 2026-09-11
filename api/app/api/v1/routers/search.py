"""Global search across hosts, jobs, runs, profiles, and remediations."""

from fastapi import APIRouter, Depends, Query
from sqlalchemy import String, cast, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import AuthUser
from app.core.roles import require_operate
from app.core.database import get_db
from app.models import Host, Job, JobRun, JobScope, Profile, RemediationJob
from app.schemas import SearchResponse, SearchResultItem
from app.services.object_rbac import apply_owner_scope

router = APIRouter()

_DEFAULT_LIMIT = 25
_DEFAULT_PER_TYPE = 5


def _like(q: str) -> str:
    return f"%{q}%"


def _score(*candidates: str | None, query: str) -> int:
    ql = query.lower()
    best = 0
    for raw in candidates:
        if not raw:
            continue
        value = raw.lower()
        if value == ql:
            best = max(best, 100)
        elif value.startswith(ql):
            best = max(best, 80)
        elif ql in value:
            best = max(best, 50)
        else:
            best = max(best, 10)
    return best


def _scope_value(scope: object | None) -> str:
    if scope is None:
        return JobScope.STANDARD.value
    return scope.value if hasattr(scope, "value") else str(scope)


def _execution_type_value(execution_type: object | None) -> str | None:
    if execution_type is None:
        return None
    return execution_type.value if hasattr(execution_type, "value") else str(execution_type)


def _job_href(job_id: int, *, scope: object | None, execution_type: object | None) -> str:
    if _scope_value(scope) == JobScope.NETWORK.value:
        return f"/network/jobs?edit={job_id}"
    exec_type = (_execution_type_value(execution_type) or "").lower()
    platform = "windows" if exec_type == "winrm" else "linux"
    return f"/jobs?edit={job_id}&platform={platform}"


def _remediation_href(job_id: int, *, scope: object | None, execution_type: object | None) -> str:
    if _scope_value(scope) == JobScope.NETWORK.value:
        return f"/network/remediation?edit={job_id}"
    exec_type = (_execution_type_value(execution_type) or "").lower()
    platform = "windows" if exec_type == "winrm" else "linux"
    return f"/remediation?edit={job_id}&platform={platform}"


@router.get("", response_model=SearchResponse)
async def global_search(
    q: str = Query(default="", max_length=200),
    limit: int = Query(default=_DEFAULT_LIMIT, ge=1, le=50),
    per_type: int = Query(default=_DEFAULT_PER_TYPE, ge=1, le=20),
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_operate),
) -> SearchResponse:
    query = q.strip()
    if not query:
        return SearchResponse(items=[], query=query)

    pattern = _like(query)
    items: list[SearchResultItem] = []

    host_stmt = (
        select(Host)
        .where(
            Host.is_ephemeral.is_(False),
            or_(Host.name.ilike(pattern), Host.hostname.ilike(pattern)),
        )
        .order_by(Host.name.asc())
        .limit(per_type)
    )
    host_stmt = apply_owner_scope(host_stmt, Host.owner_sub, user)
    host_rows = (await db.execute(host_stmt)).scalars().all()
    for host in host_rows:
        items.append(
            SearchResultItem(
                type="host",
                id=host.id,
                title=host.name,
                subtitle=host.hostname,
                href=f"/hosts?edit={host.id}",
                score=_score(host.name, host.hostname, query=query),
            )
        )

    job_stmt = select(Job).where(Job.name.ilike(pattern)).order_by(Job.name.asc()).limit(per_type)
    job_stmt = apply_owner_scope(job_stmt, Job.owner_sub, user)
    job_rows = (await db.execute(job_stmt)).scalars().all()
    for job in job_rows:
        items.append(
            SearchResultItem(
                type="job",
                id=job.id,
                title=job.name,
                subtitle=f"Job #{job.id}",
                href=_job_href(job.id, scope=job.scope, execution_type=job.execution_type),
                score=_score(job.name, query=query),
            )
        )

    run_filters = [Job.name.ilike(pattern), cast(JobRun.status, String).ilike(pattern)]
    if query.isdigit():
        run_filters.append(JobRun.id == int(query))
    run_stmt = (
        select(JobRun, Job)
        .join(Job, Job.id == JobRun.job_id)
        .where(or_(*run_filters))
        .order_by(JobRun.id.desc())
        .limit(per_type)
    )
    run_stmt = apply_owner_scope(run_stmt, Job.owner_sub, user)
    run_rows = (await db.execute(run_stmt)).all()
    for job_run, job in run_rows:
        status_value = job_run.status.value if hasattr(job_run.status, "value") else str(job_run.status)
        items.append(
            SearchResultItem(
                type="run",
                id=job_run.id,
                title=f"Run #{job_run.id}",
                subtitle=f"{job.name} · {status_value}",
                href=f"/reports?run={job_run.id}",
                score=_score(str(job_run.id), job.name, status_value, query=query),
            )
        )

    profile_rows = (
        await db.execute(
            select(Profile)
            .where(
                or_(
                    Profile.profile_name.ilike(pattern),
                    Profile.profile_title.ilike(pattern),
                    Profile.summary.ilike(pattern),
                    Profile.os_name.ilike(pattern),
                )
            )
            .order_by(Profile.profile_name.asc())
            .limit(per_type)
        )
    ).scalars().all()
    for profile in profile_rows:
        subtitle_parts = [profile.profile_name]
        if profile.version:
            subtitle_parts.append(f"v{profile.version}")
        if profile.os_name:
            subtitle_parts.append(profile.os_name)
        items.append(
            SearchResultItem(
                type="profile",
                id=profile.id,
                title=profile.profile_name,
                subtitle=" · ".join(subtitle_parts),
                href=f"/profiles?id={profile.id}",
                score=_score(
                    profile.profile_name,
                    profile.profile_title,
                    profile.summary,
                    profile.os_name,
                    query=query,
                ),
            )
        )

    remediation_stmt = (
        select(RemediationJob)
        .where(RemediationJob.name.ilike(pattern))
        .order_by(RemediationJob.name.asc())
        .limit(per_type)
    )
    remediation_stmt = apply_owner_scope(remediation_stmt, RemediationJob.owner_sub, user)
    remediation_rows = (await db.execute(remediation_stmt)).scalars().all()
    for rem in remediation_rows:
        items.append(
            SearchResultItem(
                type="remediation",
                id=rem.id,
                title=rem.name,
                subtitle=f"Remediation #{rem.id}",
                href=_remediation_href(rem.id, scope=rem.scope, execution_type=rem.execution_type),
                score=_score(rem.name, query=query),
            )
        )

    items.sort(key=lambda item: (-(item.score or 0), item.type, item.title.lower()))
    return SearchResponse(items=items[:limit], query=query)
