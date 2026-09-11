from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import AuthUser, require_roles
from app.core.roles import require_operate, require_reports
from app.core.config import settings
from app.core.database import get_db
from app.models import Profile, UserRole
from app.schemas import (
    CheckScriptContentRead,
    CheckScriptContentUpdate,
    CheckScriptRead,
    ScapProfilePreview,
    ProfileCreate,
    ProfileDetail,
    ProfileDependencies,
    ProfileRead,
    ProfileRuleChangelogEntry,
    ProfileRuleRead,
    ProfileRuleUpdate,
    ProfileRuleUpdateResult,
    ProfileSyncResult,
    ProfilesBulkActionRequest,
    ProfilesBulkActionResult,
    ProfilesBulkActionError,
    ProfilesBulkImportRequest,
    ProfilesBulkImportResult,
    ProfilesCatalogEntry,
    ProfilesCatalogSyncStatus,
)
from app.services.scap import preview_xccdf_profiles_from_uploads
from app.services.profiles import ProfileActiveRunsError, ProfileDependencyError, ProfileService
from app.services.audit_log import log_audit_event
from secaudit_core.profiles_catalog import iter_catalog_entries_from_imports

import json

router = APIRouter()
profile_service = ProfileService()


def _profile_delete_conflict_detail(exc: ProfileDependencyError | ProfileActiveRunsError) -> dict:
    return {
        "code": exc.code,
        "message": str(exc),
        "dependencies": exc.dependencies.model_dump(),
    }


def _profile_read(profile, *, latest_versions: dict[str, str] | None = None) -> ProfileRead:
    payload = profile_service.enrich_profile_read(profile, latest_versions)
    return ProfileRead.model_validate(payload)


def _profile_detail(profile) -> ProfileDetail:
    from app.models import ScriptKind

    detail = ProfileDetail.model_validate(profile)
    detail.category_name = profile.category.name if profile.category else None
    detail.check_scripts = [
        CheckScriptRead.model_validate(script)
        for script in profile.check_scripts
        if script.script_kind == ScriptKind.AUDIT
    ]
    detail.remediation_scripts = [
        CheckScriptRead.model_validate(script)
        for script in profile.check_scripts
        if script.script_kind == ScriptKind.REMEDIATION
    ]
    return detail


@router.get("", response_model=list[ProfileRead])
async def list_profiles(
    category_id: int | None = Query(default=None),
    os_name: str | None = Query(default=None),
    os_version: str | None = Query(default=None),
    os: str | None = Query(default=None, description="OS slug, e.g. linux"),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_reports),
) -> list[ProfileRead]:
    profiles = await profile_service.list_profiles(
        db,
        category_id=category_id,
        os_name=os_name,
        os_version=os_version,
        os=os,
    )
    latest_versions = await profile_service.catalog_latest_versions(db)
    return [_profile_read(s, latest_versions=latest_versions) for s in profiles]


@router.get("/discover", response_model=list[str])
async def discover_profiles(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_operate),
) -> list[str]:
    return await profile_service.scan_profiles_directory(db)


@router.get("/catalog", response_model=list[ProfilesCatalogEntry])
async def list_profiles_catalog(
    family: str | None = Query(default=None, pattern="^(custom)$"),
    platform: str | None = Query(default=None, pattern="^(linux|windows|network)$"),
    os_name: str | None = Query(default=None),
    os_version: str | None = Query(default=None),
    os: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_operate),
) -> list[ProfilesCatalogEntry]:
    entries = await profile_service.list_catalog(
        db,
        family=family,
        platform=platform,
        os_name=os_name,
        os_version=os_version,
        os=os,
    )
    return [ProfilesCatalogEntry.model_validate(entry) for entry in entries]


@router.get("/catalog/sync-status", response_model=ProfilesCatalogSyncStatus)
async def get_profiles_catalog_sync_status(
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_operate),
) -> ProfilesCatalogSyncStatus:
    status = await profile_service.get_catalog_sync_status(db)
    return ProfilesCatalogSyncStatus.model_validate(status)


@router.get("/catalog/stream")
async def stream_profiles_catalog(
    family: str | None = Query(default=None, pattern="^(custom)$"),
    platform: str | None = Query(default=None, pattern="^(linux|windows|network)$"),
    os_name: str | None = Query(default=None),
    os_version: str | None = Query(default=None),
    os: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_operate),
) -> StreamingResponse:
    from secaudit_core.profiles_catalog import os_slug as catalog_os_slug

    result = await db.execute(
        select(Profile.profile_name, Profile.version, Profile.id, Profile.package_path)
    )
    imported_rows = [
        (row.profile_name, row.version, row.id, row.package_path) for row in result.all()
    ]

    def generate():
        for entry in iter_catalog_entries_from_imports(
            settings.profiles_path,
            imported_rows=imported_rows,
            family=family,
        ):
            if platform and entry.get("platform") != platform:
                continue
            if os_name and os_name.strip().lower() not in str(entry.get("os_name") or "").lower():
                continue
            if os_version and os_version.strip().lower() not in str(entry.get("os_version") or "").lower():
                continue
            if os:
                os_filter = os.strip().lower()
                entry_os = str(entry.get("os_name") or "").lower()
                if catalog_os_slug(entry.get("os_name")) != os_filter and entry_os != os_filter:
                    continue
            yield json.dumps(entry, ensure_ascii=False) + "\n"
        yield json.dumps({"type": "done"}, ensure_ascii=False) + "\n"

    return StreamingResponse(generate(), media_type="application/x-ndjson")


@router.post("/import/bulk", response_model=ProfilesBulkImportResult)
async def import_profiles_bulk(
    data: ProfilesBulkImportRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> ProfilesBulkImportResult:
    result = await profile_service.import_bulk(
        db,
        data.package_paths,
        skip_existing=data.skip_existing,
        update_existing=data.update_existing,
    )
    for profile in result["imported"]:
        await log_audit_event(
            db,
            request,
            user,
            action="profile.import",
            resource_type="profile",
            resource_id=profile.id,
            resource_name=profile.profile_name,
        )
    return ProfilesBulkImportResult(
        imported=[_profile_read(profile) for profile in result["imported"]],
        skipped=result["skipped"],
        errors=result["errors"],
    )


@router.post("/bulk/enable", response_model=ProfilesBulkActionResult)
async def bulk_enable_profiles(
    data: ProfilesBulkActionRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> ProfilesBulkActionResult:
    result = await profile_service.bulk_set_active(db, data.profile_ids, is_active=True)
    if result["succeeded"]:
        await log_audit_event(
            db,
            request,
            user,
            action="profile.bulk_enable",
            resource_type="profile",
            metadata={"profile_ids": result["succeeded"]},
        )
    return ProfilesBulkActionResult(
        succeeded=result["succeeded"],
        failed=[ProfilesBulkActionError.model_validate(item) for item in result["failed"]],
    )


@router.post("/bulk/disable", response_model=ProfilesBulkActionResult)
async def bulk_disable_profiles(
    data: ProfilesBulkActionRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> ProfilesBulkActionResult:
    result = await profile_service.bulk_set_active(db, data.profile_ids, is_active=False)
    if result["succeeded"]:
        await log_audit_event(
            db,
            request,
            user,
            action="profile.bulk_disable",
            resource_type="profile",
            metadata={"profile_ids": result["succeeded"]},
        )
    return ProfilesBulkActionResult(
        succeeded=result["succeeded"],
        failed=[ProfilesBulkActionError.model_validate(item) for item in result["failed"]],
    )


@router.post("/bulk/delete", response_model=ProfilesBulkActionResult)
async def bulk_delete_profiles(
    data: ProfilesBulkActionRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> ProfilesBulkActionResult:
    result = await profile_service.bulk_delete(db, data.profile_ids, cascade=data.cascade)
    if result["succeeded"]:
        await log_audit_event(
            db,
            request,
            user,
            action="profile.bulk_delete",
            resource_type="profile",
            metadata={"profile_ids": result["succeeded"], "cascade": data.cascade},
        )
    return ProfilesBulkActionResult(
        succeeded=result["succeeded"],
        failed=[ProfilesBulkActionError.model_validate(item) for item in result["failed"]],
    )


@router.post("/bulk/sync", response_model=ProfilesBulkActionResult)
async def bulk_sync_profiles(
    data: ProfilesBulkActionRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> ProfilesBulkActionResult:
    result = await profile_service.bulk_sync(db, data.profile_ids)
    if result["succeeded"]:
        await log_audit_event(
            db,
            request,
            user,
            action="profile.bulk_sync",
            resource_type="profile",
            metadata={"profile_ids": result["succeeded"]},
        )
    return ProfilesBulkActionResult(
        succeeded=result["succeeded"],
        failed=[ProfilesBulkActionError.model_validate(item) for item in result["failed"]],
    )


@router.post("/import/preview-profiles", response_model=list[ScapProfilePreview])
async def preview_scap_profiles(
    files: list[UploadFile] = File(...),
    _: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> list[ScapProfilePreview]:
    uploads: list[tuple[str, bytes]] = []
    for upload in files:
        uploads.append((upload.filename or "file", await upload.read()))
    profiles = preview_xccdf_profiles_from_uploads(uploads)
    return [ScapProfilePreview.model_validate(item) for item in profiles]


@router.get("/catalog/preview-rules", response_model=list[ProfileRuleRead])
async def preview_catalog_rules(
    package_path: str,
    limit: int = Query(default=200, ge=1, le=1000),
    _: AuthUser = Depends(require_operate),
) -> list[ProfileRuleRead]:
    try:
        rules = await profile_service.preview_catalog_rules(package_path, limit=limit)
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return [ProfileRuleRead.model_validate(rule) for rule in rules]


@router.get("/{profile_id}", response_model=ProfileDetail)
async def get_profile(
    profile_id: int,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_reports),
) -> ProfileDetail:
    profile = await profile_service.get_profile(db, profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    return _profile_detail(profile)


@router.get("/{profile_id}/rules", response_model=list[ProfileRuleRead])
async def get_profile_rules(
    profile_id: int,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_reports),
) -> list[ProfileRuleRead]:
    try:
        rules = await profile_service.get_profile_rules(db, profile_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return [ProfileRuleRead.model_validate(rule) for rule in rules]


@router.get(
    "/{profile_id}/rules/changelog",
    response_model=list[ProfileRuleChangelogEntry],
)
async def get_profile_rule_changelog(
    profile_id: int,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_reports),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[ProfileRuleChangelogEntry]:
    try:
        entries = await profile_service.get_profile_rule_changelog(db, profile_id, limit=limit)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return [ProfileRuleChangelogEntry.model_validate(entry) for entry in entries]


@router.patch(
    "/{profile_id}/rules/{requirement_id}",
    response_model=ProfileRuleUpdateResult,
)
async def update_profile_rule(
    profile_id: int,
    requirement_id: str,
    data: ProfileRuleUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> ProfileRuleUpdateResult:
    updates = data.model_dump(exclude_unset=True)
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    try:
        result = await profile_service.update_profile_rule(
            db,
            profile_id,
            requirement_id,
            updates,
            actor=user.username,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    await log_audit_event(
        db,
        request,
        user,
        action="profile.rule.update",
        resource_type="profile",
        resource_id=profile_id,
        resource_name=requirement_id,
        metadata={
            "requirement_id": requirement_id,
            "profile_version_before": result.get("profile_version_before"),
            "profile_version_after": result.get("profile_version"),
            "changes": result.get("changes"),
        },
    )
    return ProfileRuleUpdateResult.model_validate(
        {
            "rule": result["rule"],
            "profile_version": result["profile_version"],
            "changelog_entry": result["changelog_entry"],
        }
    )


@router.get("/{profile_id}/scripts/{script_id}/content", response_model=CheckScriptContentRead)
async def get_check_script_content(
    profile_id: int,
    script_id: int,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> CheckScriptContentRead:
    try:
        payload = await profile_service.get_check_script_content(db, profile_id, script_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return CheckScriptContentRead.model_validate(payload)


@router.put("/{profile_id}/scripts/{script_id}/content", response_model=CheckScriptContentRead)
async def update_check_script_content(
    profile_id: int,
    script_id: int,
    data: CheckScriptContentUpdate,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_roles(UserRole.ADMIN)),
) -> CheckScriptContentRead:
    try:
        payload = await profile_service.update_check_script_content(
            db, profile_id, script_id, data.content
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return CheckScriptContentRead.model_validate(payload)


@router.post("", response_model=ProfileRead, status_code=201)
async def create_profile(
    data: ProfileCreate,
    db: AsyncSession = Depends(get_db),
    _: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> ProfileRead:
    profile = await profile_service.create_profile(db, data)
    return _profile_read(profile)


@router.post("/import", response_model=ProfileRead, status_code=201)
async def import_profile(
    package_path: str,
    request: Request,
    category_id: int | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> ProfileRead:
    try:
        profile = await profile_service.import_from_path(db, package_path, category_id)
    except FileNotFoundError as exc:
        message = str(exc)
        status = 404 if "package directory not found" in message.lower() else 400
        raise HTTPException(status_code=status, detail=message) from exc
    except ValueError as exc:
        status = 404 if str(exc) == "Category not found" else 409
        raise HTTPException(status_code=status, detail=str(exc)) from exc
    await log_audit_event(
        db,
        request,
        user,
        action="profile.import",
        resource_type="profile",
        resource_id=profile.id,
        resource_name=profile.profile_name,
    )
    return _profile_read(profile)


@router.post("/import/upload", response_model=ProfileRead, status_code=201)
async def import_profile_upload(
    request: Request,
    files: list[UploadFile] = File(...),
    compliance_playbook: UploadFile | None = File(default=None),
    category_id: int | None = Query(default=None),
    scap_profile_id: str | None = Query(default=None),
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> ProfileRead:
    uploads: list[tuple[str, bytes]] = []
    for upload in files:
        content = await upload.read()
        filename = upload.filename or "file"
        uploads.append((filename, content))

    compliance_payload: tuple[str, bytes] | None = None
    if compliance_playbook is not None and compliance_playbook.filename:
        compliance_payload = (
            compliance_playbook.filename,
            await compliance_playbook.read(),
        )

    try:
        profile = await profile_service.import_from_upload(
            db,
            uploads,
            category_id,
            scap_profile_id=scap_profile_id,
            compliance_playbook=compliance_payload,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        message = str(exc)
        if message == "Category not found" or message.startswith("Category not found for slug"):
            status = 404
        elif "already imported" in message:
            status = 409
        else:
            status = 400
        raise HTTPException(status_code=status, detail=message) from exc
    await log_audit_event(
        db,
        request,
        user,
        action="profile.import",
        resource_type="profile",
        resource_id=profile.id,
        resource_name=profile.profile_name,
    )
    return _profile_read(profile)


@router.post("/{profile_id}/sync", response_model=ProfileSyncResult)
async def sync_profile(
    profile_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> ProfileSyncResult:
    profile = await profile_service.get_profile(db, profile_id)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    previous_version = profile.version
    try:
        updated_profile = await profile_service.sync_profile(db, profile_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    await log_audit_event(
        db,
        request,
        user,
        action="profile.sync",
        resource_type="profile",
        resource_id=profile_id,
        resource_name=updated_profile.profile_name,
        metadata={"previous_version": previous_version, "new_version": updated_profile.version},
    )
    latest_versions = await profile_service.catalog_latest_versions(db)
    return ProfileSyncResult(
        profile=_profile_read(updated_profile, latest_versions=latest_versions),
        updated=updated_profile.version != previous_version,
    )


@router.get("/{profile_id}/dependencies", response_model=ProfileDependencies)
async def get_profile_dependencies(
    profile_id: int,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_operate),
) -> ProfileDependencies:
    try:
        return await profile_service.get_profile_dependencies(db, profile_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.delete("/{profile_id}", status_code=204)
async def delete_profile(
    profile_id: int,
    request: Request,
    cascade: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_roles(UserRole.OPERATOR, UserRole.ADMIN)),
) -> None:
    profile = await profile_service.get_profile(db, profile_id)
    try:
        await profile_service.delete_profile(db, profile_id, cascade=cascade)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ProfileDependencyError, ProfileActiveRunsError) as exc:
        raise HTTPException(status_code=409, detail=_profile_delete_conflict_detail(exc)) from exc
    await log_audit_event(
        db,
        request,
        user,
        action="profile.delete",
        resource_type="profile",
        resource_id=profile_id,
        resource_name=profile.profile_name if profile else None,
        metadata={"cascade": cascade},
    )
