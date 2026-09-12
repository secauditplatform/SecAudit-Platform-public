from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.auth import AuthUser, require_roles
from app.core.roles import require_operate
from app.core.config import settings
from app.core.database import get_db
from app.core.blocking import run_blocking
from app.models import Playbook, PlaybookKind, Profile, UserRole, JobScope
from app.schemas import (
    PlaybookChangelogEntry,
    PlaybookContentUpdate,
    PlaybookContentUpdateResult,
    PlaybookCreate,
    PlaybookRead,
    PlaybookRunRead,
    PlaybookRunRequest,
    PlaybookTemplateRead,
    PlaybookUpdate,
    PlaybookValidateResponse,
)
from app.services.object_rbac import (
    assert_can_access,
    assert_can_mutate,
    assign_owner,
)
from app.services.playbook_templates import list_playbook_templates
from app.services.playbook_validate import validate_playbook_content
from app.services.playbooks import PlaybookService
from app.services.audit_log import log_audit_event
from secaudit_core.object_rbac import applies_engineer_scope
from secaudit_core.profile_packages import normalize_playbook_version
from app.services.object_rbac import rbac_enabled

router = APIRouter()
playbook_service = PlaybookService()


def _assert_playbook_access(user: AuthUser, playbook: Playbook, *, mutate: bool = False) -> None:
    if playbook.kind == PlaybookKind.COMPLIANCE_TEMPLATE:
        return
    if mutate:
        assert_can_mutate(user, playbook.owner_sub, detail="Playbook not found")
    else:
        assert_can_access(user, playbook.owner_sub, detail="Playbook not found")


def _playbook_read(playbook: Playbook) -> PlaybookRead:
    payload = PlaybookRead.model_validate(playbook)
    payload.version = normalize_playbook_version(playbook.version)
    if playbook.profile is not None:
        payload.profile_name = playbook.profile.profile_name
    return payload


@router.get("", response_model=list[PlaybookRead])
async def list_playbooks(
    scope: JobScope | None = Query(default=None),
    platform: str | None = Query(default=None, pattern="^(linux|windows|network)$"),
    kind: str | None = Query(default=None, pattern="^(user|compliance_template)$"),
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_operate),
) -> list[PlaybookRead]:
    stmt = select(Playbook).options(selectinload(Playbook.profile)).order_by(Playbook.name)
    if scope is not None:
        stmt = stmt.where(Playbook.scope == scope)
    if platform is not None:
        stmt = stmt.where(Playbook.platform == platform)
    if kind is not None:
        stmt = stmt.where(Playbook.kind == PlaybookKind(kind))
    if applies_engineer_scope(user.roles, enabled=rbac_enabled()):
        stmt = stmt.where(
            or_(
                Playbook.owner_sub == user.sub,
                Playbook.kind == PlaybookKind.COMPLIANCE_TEMPLATE,
            )
        )
    result = await db.execute(stmt)
    return [_playbook_read(item) for item in result.scalars().all()]


@router.get("/templates", response_model=list[PlaybookTemplateRead])
async def get_playbook_templates(
    scope: JobScope | None = Query(default=None),
    _: AuthUser = Depends(require_operate),
) -> list[PlaybookTemplateRead]:
    items = list_playbook_templates()
    if scope is not None:
        items = [item for item in items if item.get("scope", JobScope.STANDARD.value) == scope.value]
    return [PlaybookTemplateRead.model_validate(item) for item in items]


@router.get("/runs", response_model=list[PlaybookRunRead])
async def list_playbook_runs(
    playbook_id: int | None = Query(default=None),
    scope: JobScope | None = Query(default=None),
    platform: str | None = Query(default=None, pattern="^(linux|windows|network)$"),
    limit: int = Query(default=30, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_operate),
) -> list[PlaybookRunRead]:
    runs = await playbook_service.list_playbook_runs(
        db, user, playbook_id=playbook_id, scope=scope, platform=platform, limit=limit
    )
    return [PlaybookRunRead.model_validate(item) for item in runs]


@router.get("/runs/{run_id}", response_model=PlaybookRunRead)
async def get_playbook_run(
    run_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_operate),
) -> PlaybookRunRead:
    try:
        run = await playbook_service.get_playbook_run(db, user, run_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return PlaybookRunRead.model_validate(run)


@router.post("/validate", response_model=PlaybookValidateResponse)
async def validate_playbook_body(
    data: PlaybookCreate,
    _: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> PlaybookValidateResponse:
    try:
        return await run_blocking(
            validate_playbook_content,
            data.content,
            timeout=settings.blocking_io_timeout_seconds,
        )
    except TimeoutError as exc:
        raise HTTPException(status_code=504, detail="Playbook validation timed out") from exc


@router.get("/{playbook_id}/changelog", response_model=list[PlaybookChangelogEntry])
async def get_playbook_changelog(
    playbook_id: int,
    limit: int = Query(default=100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_operate),
) -> list[PlaybookChangelogEntry]:
    playbook = await db.get(Playbook, playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    _assert_playbook_access(user, playbook)
    if playbook.kind != PlaybookKind.COMPLIANCE_TEMPLATE:
        return []
    if not playbook.profile_id:
        return []
    profile = await db.get(Profile, playbook.profile_id)
    if not profile or not profile.package_path:
        return []
    from secaudit_core.profile_packages import load_playbook_changelog

    entries = load_playbook_changelog(Path(profile.package_path), limit=limit)
    return [PlaybookChangelogEntry.model_validate(item) for item in entries]


@router.patch("/{playbook_id}/content", response_model=PlaybookContentUpdateResult)
async def update_playbook_content(
    playbook_id: int,
    data: PlaybookContentUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> PlaybookContentUpdateResult:
    result = await db.execute(
        select(Playbook).options(selectinload(Playbook.profile)).where(Playbook.id == playbook_id)
    )
    playbook = result.scalar_one_or_none()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    _assert_playbook_access(user, playbook, mutate=True)

    try:
        validation = await run_blocking(
            validate_playbook_content,
            data.content,
            timeout=settings.blocking_io_timeout_seconds,
        )
    except TimeoutError as exc:
        raise HTTPException(status_code=504, detail="Playbook validation timed out") from exc
    if not validation.valid:
        raise HTTPException(status_code=400, detail=validation.message)

    if playbook.kind == PlaybookKind.COMPLIANCE_TEMPLATE:
        profile = playbook.profile
        if profile is None or not profile.package_path:
            raise HTTPException(status_code=400, detail="Compliance playbook has no linked profile package")
        from secaudit_core.profile_packages import update_compliance_playbook_in_package

        try:
            updated = update_compliance_playbook_in_package(
                Path(profile.package_path),
                data.content,
                actor=user.username or user.sub,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

        playbook.content = updated["content"]
        playbook.version = updated["playbook_version"]
        await db.flush()
        await db.refresh(playbook)
        await log_audit_event(
            db,
            request,
            user,
            action="playbook.content.update",
            resource_type="playbook",
            resource_id=playbook.id,
            resource_name=playbook.name,
            metadata={"playbook_version": playbook.version},
        )
        return PlaybookContentUpdateResult(
            playbook=_playbook_read(playbook),
            playbook_version=updated["playbook_version"],
            changelog_entry=PlaybookChangelogEntry.model_validate(updated["changelog_entry"]),
        )

    # Regular user playbooks: content update without package changelog.
    from datetime import UTC, datetime
    from uuid import uuid4

    version_before = normalize_playbook_version(playbook.version)
    from secaudit_core.profile_packages import bump_semver_patch

    version_after = bump_semver_patch(version_before)
    playbook.content = data.content.replace("\r\n", "\n")
    playbook.version = version_after
    await db.flush()
    await db.refresh(playbook)
    entry = {
        "id": str(uuid4()),
        "at": datetime.now(UTC).isoformat(),
        "actor": user.username or user.sub,
        "playbook_version_before": version_before,
        "playbook_version_after": version_after,
        "changes": {"content": {"from": None, "to": "(updated)"}},
    }
    await log_audit_event(
        db,
        request,
        user,
        action="playbook.content.update",
        resource_type="playbook",
        resource_id=playbook.id,
        resource_name=playbook.name,
        metadata={"playbook_version": playbook.version},
    )
    return PlaybookContentUpdateResult(
        playbook=_playbook_read(playbook),
        playbook_version=version_after,
        changelog_entry=PlaybookChangelogEntry.model_validate(entry),
    )


@router.get("/{playbook_id}", response_model=PlaybookRead)
async def get_playbook(
    playbook_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_operate),
) -> PlaybookRead:
    result = await db.execute(
        select(Playbook).options(selectinload(Playbook.profile)).where(Playbook.id == playbook_id)
    )
    playbook = result.scalar_one_or_none()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    _assert_playbook_access(user, playbook)
    return _playbook_read(playbook)


@router.post("", response_model=PlaybookRead, status_code=201)
async def create_playbook(
    data: PlaybookCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> PlaybookRead:
    existing = await db.execute(select(Playbook).where(Playbook.name == data.name))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Playbook name already exists")
    payload = data.model_dump()
    if payload.get("scope") == JobScope.NETWORK:
        payload["platform"] = "network"
    playbook = Playbook(**payload, kind=PlaybookKind.USER, version="1.0")
    assign_owner(playbook, user)
    db.add(playbook)
    await db.flush()
    await db.refresh(playbook)
    await log_audit_event(
        db,
        request,
        user,
        action="playbook.create",
        resource_type="playbook",
        resource_id=playbook.id,
        resource_name=playbook.name,
    )
    return _playbook_read(playbook)


@router.post("/{playbook_id}/run", response_model=PlaybookRunRead, status_code=201)
async def run_playbook(
    playbook_id: int,
    data: PlaybookRunRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> PlaybookRunRead:
    playbook = await db.get(Playbook, playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    _assert_playbook_access(user, playbook, mutate=True)
    if not playbook.is_active:
        raise HTTPException(status_code=409, detail="Playbook is inactive")

    try:
        job_run = await playbook_service.run_playbook(
            db, user, playbook, data.host_ids, connection_mode=data.connection_mode
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        await log_audit_event(
            db,
            request,
            user,
            action="playbook.run",
            resource_type="playbook",
            resource_id=playbook_id,
            resource_name=playbook.name if playbook else None,
            outcome="failed",
            metadata={"error": str(exc)},
        )
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    await log_audit_event(
        db,
        request,
        user,
        action="playbook.run",
        resource_type="playbook",
        resource_id=playbook.id,
        resource_name=playbook.name,
        metadata={"run_id": job_run.id},
    )
    return PlaybookRunRead(
        id=job_run.id,
        job_id=job_run.job_id,
        playbook_id=playbook.id,
        playbook_name=playbook.name,
        status=job_run.status,
        started_at=job_run.started_at,
        finished_at=job_run.finished_at,
        error_message=job_run.error_message,
        created_at=job_run.created_at,
        host_count=len(data.host_ids),
    )


@router.put("/{playbook_id}", response_model=PlaybookRead)
async def update_playbook(
    playbook_id: int,
    data: PlaybookUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> PlaybookRead:
    result = await db.execute(
        select(Playbook).options(selectinload(Playbook.profile)).where(Playbook.id == playbook_id)
    )
    playbook = result.scalar_one_or_none()
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    _assert_playbook_access(user, playbook, mutate=True)
    updates = data.model_dump(exclude_unset=True)
    if playbook.kind == PlaybookKind.COMPLIANCE_TEMPLATE and "content" in updates:
        # Content edits for compliance templates must go through versioned endpoint.
        updates.pop("content", None)
    for key, value in updates.items():
        setattr(playbook, key, value)
    await db.flush()
    await db.refresh(playbook)
    await log_audit_event(
        db,
        request,
        user,
        action="playbook.update",
        resource_type="playbook",
        resource_id=playbook.id,
        resource_name=playbook.name,
    )
    return _playbook_read(playbook)


@router.delete("/{playbook_id}", status_code=204)
async def delete_playbook(
    playbook_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> None:
    playbook = await db.get(Playbook, playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    _assert_playbook_access(user, playbook, mutate=True)
    try:
        await playbook_service.delete_playbook(db, playbook)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    await log_audit_event(
        db,
        request,
        user,
        action="playbook.delete",
        resource_type="playbook",
        resource_id=playbook_id,
        resource_name=playbook.name,
    )
