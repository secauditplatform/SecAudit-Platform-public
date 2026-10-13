"""Import and clear the customer CVE feed. The feed is local and optional."""

from datetime import datetime

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.auth import AuthUser
from app.core.database import get_db
from app.core.roles import require_admin, require_reports
from app.services.audit_log import log_audit_event
from app.services.cve_feed import (
    CveFeedError,
    CveFeedMissing,
    add_feed_entry,
    delete_feed_entry,
    feed_status,
    parse_cve_feed,
    parse_feed_entry,
    replace_feed,
    update_feed_entry,
)

router = APIRouter()


class CveFeedEntryRead(BaseModel):
    id: int
    cve_id: str
    requirement_id: str
    profile_name: str
    summary: str | None = None


class CveFeedEntryWrite(BaseModel):
    cve_id: str
    requirement_id: str = ""
    profile_name: str = ""
    summary: str | None = None


class CveFeedStatusRead(BaseModel):
    loaded: bool
    entry_count: int
    imported_at: datetime | None = None
    entries: list[CveFeedEntryRead] = []


def _status_read(status) -> CveFeedStatusRead:
    imported_at = status.imported_at if isinstance(status.imported_at, datetime) else None
    return CveFeedStatusRead(
        loaded=status.loaded,
        entry_count=status.entry_count,
        imported_at=imported_at,
        entries=[
            CveFeedEntryRead(
                id=entry.id,
                cve_id=entry.cve_id,
                requirement_id=entry.requirement_id,
                profile_name=entry.profile_name,
                summary=entry.summary,
            )
            for entry in status.entries
        ],
    )


@router.get("", response_model=CveFeedStatusRead)
async def get_cve_feed(
    db: AsyncSession = Depends(get_db),
    _user: AuthUser = Depends(require_reports),
) -> CveFeedStatusRead:
    return _status_read(await feed_status(db))


@router.put("", response_model=CveFeedStatusRead)
async def put_cve_feed(
    request: Request,
    payload: dict = Body(...),
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_admin),
) -> CveFeedStatusRead:
    try:
        entries = parse_cve_feed(payload)
    except CveFeedError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    await replace_feed(db, entries)
    await log_audit_event(
        db,
        request,
        user,
        action="cve_feed.replace",
        resource_type="cve_feed",
        resource_name="secaudit.cve_feed",
        metadata={"entry_count": len(entries)},
    )
    return _status_read(await feed_status(db))


@router.delete("", response_model=CveFeedStatusRead)
async def delete_cve_feed(
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_admin),
) -> CveFeedStatusRead:
    await replace_feed(db, [])
    await log_audit_event(
        db,
        request,
        user,
        action="cve_feed.clear",
        resource_type="cve_feed",
        resource_name="secaudit.cve_feed",
        metadata={"entry_count": 0},
    )
    return _status_read(await feed_status(db))


def _entry_or_400(payload: CveFeedEntryWrite):
    try:
        return parse_feed_entry(payload.model_dump())
    except CveFeedError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


async def _mutate(action) -> None:
    try:
        await action()
    except CveFeedMissing as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except CveFeedError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@router.post("/entries", response_model=CveFeedStatusRead)
async def post_cve_feed_entry(
    request: Request,
    payload: CveFeedEntryWrite,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_admin),
) -> CveFeedStatusRead:
    entry = _entry_or_400(payload)
    await _mutate(lambda: add_feed_entry(db, entry))
    await log_audit_event(
        db,
        request,
        user,
        action="cve_feed.entry_add",
        resource_type="cve_feed",
        resource_name=entry.cve_id,
        metadata={"requirement_id": entry.requirement_id, "profile_name": entry.profile_name},
    )
    return _status_read(await feed_status(db))


@router.patch("/entries/{entry_id}", response_model=CveFeedStatusRead)
async def patch_cve_feed_entry(
    entry_id: int,
    request: Request,
    payload: CveFeedEntryWrite,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_admin),
) -> CveFeedStatusRead:
    entry = _entry_or_400(payload)
    await _mutate(lambda: update_feed_entry(db, entry_id, entry))
    await log_audit_event(
        db,
        request,
        user,
        action="cve_feed.entry_update",
        resource_type="cve_feed",
        resource_id=str(entry_id),
        resource_name=entry.cve_id,
        metadata={"requirement_id": entry.requirement_id, "profile_name": entry.profile_name},
    )
    return _status_read(await feed_status(db))


@router.delete("/entries/{entry_id}", response_model=CveFeedStatusRead)
async def delete_cve_feed_entry(
    entry_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user: AuthUser = Depends(require_admin),
) -> CveFeedStatusRead:
    await _mutate(lambda: delete_feed_entry(db, entry_id))
    await log_audit_event(
        db,
        request,
        user,
        action="cve_feed.entry_delete",
        resource_type="cve_feed",
        resource_id=str(entry_id),
        resource_name=str(entry_id),
    )
    return _status_read(await feed_status(db))
