"""Customer-supplied CVE references shown beside FAIL.

The platform does not fetch a vulnerability database and does not scan package
versions. A missing feed means there is nothing to show. References never
change check status.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

MatchedBy = Literal["rule", "package", "rule_and_package"]

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import CveFeedEntry

CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
FEED_FORMAT = "secaudit.cve_feed"
FEED_VERSION = 1
MAX_ENTRIES = 5000
MAX_SUMMARY = 500
MAX_REQUIREMENT_ID = 128
MAX_PROFILE_NAME = 256

_SPECIFICITY = {"rule_and_package": 3, "rule": 2, "package": 1}


class CveFeedError(ValueError):
    """The uploaded document is not a usable secaudit.cve_feed."""


class CveFeedMissing(CveFeedError):
    """No stored feed row has this id."""


@dataclass(frozen=True)
class FeedEntry:
    cve_id: str
    requirement_id: str
    profile_name: str
    summary: str | None


@dataclass(frozen=True)
class StoredFeedEntry:
    id: int
    cve_id: str
    requirement_id: str
    profile_name: str
    summary: str | None


@dataclass(frozen=True)
class CveReference:
    cve_id: str
    summary: str | None
    matched_by: MatchedBy


@dataclass(frozen=True)
class CveFeedStatus:
    loaded: bool
    entry_count: int
    imported_at: object | None
    entries: tuple[StoredFeedEntry, ...] = ()


def _clean_optional(value: object, *, limit: int, field: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise CveFeedError(f"{field} must be a string")
    text = value.strip()
    if len(text) > limit:
        raise CveFeedError(f"{field} is longer than {limit} characters")
    return text


def parse_cve_feed(payload: object) -> list[FeedEntry]:
    """Validate a customer feed. An empty entry list clears the feed."""
    if not isinstance(payload, dict):
        raise CveFeedError("CVE feed must be a JSON object")
    if payload.get("format") != FEED_FORMAT or payload.get("version") != FEED_VERSION:
        raise CveFeedError("CVE feed must set format to secaudit.cve_feed and version to 1")
    raw_entries = payload.get("entries")
    if not isinstance(raw_entries, list):
        raise CveFeedError("CVE feed entries must be a list")
    if len(raw_entries) > MAX_ENTRIES:
        raise CveFeedError(f"CVE feed has more than {MAX_ENTRIES} entries")

    seen: set[tuple[str, str, str]] = set()
    entries: list[FeedEntry] = []
    for index, raw in enumerate(raw_entries, start=1):
        if not isinstance(raw, dict):
            raise CveFeedError(f"Entry {index} must be an object")
        cve_id = _clean_optional(raw.get("cve_id"), limit=32, field=f"entries[{index}].cve_id").upper()
        if not CVE_ID_RE.match(cve_id):
            raise CveFeedError(f"Entry {index} cve_id must look like CVE-2024-1234")
        requirement_id = _clean_optional(
            raw.get("requirement_id"),
            limit=MAX_REQUIREMENT_ID,
            field=f"entries[{index}].requirement_id",
        )
        profile_name = _clean_optional(
            raw.get("profile_name"),
            limit=MAX_PROFILE_NAME,
            field=f"entries[{index}].profile_name",
        )
        if not requirement_id and not profile_name:
            raise CveFeedError(f"Entry {index} needs requirement_id or profile_name")
        summary_raw = raw.get("summary")
        summary: str | None
        if summary_raw is None or summary_raw == "":
            summary = None
        elif not isinstance(summary_raw, str):
            raise CveFeedError(f"Entry {index} summary must be a string")
        else:
            summary = summary_raw.strip()
            if len(summary) > MAX_SUMMARY:
                raise CveFeedError(f"Entry {index} summary is longer than {MAX_SUMMARY} characters")
            if not summary:
                summary = None
        key = (cve_id, requirement_id, profile_name)
        if key in seen:
            raise CveFeedError(f"Entry {index} repeats {cve_id} for the same rule and package")
        seen.add(key)
        entries.append(
            FeedEntry(
                cve_id=cve_id,
                requirement_id=requirement_id,
                profile_name=profile_name,
                summary=summary,
            )
        )
    return entries


def parse_feed_entry(payload: object) -> FeedEntry:
    """Validate one row from the feed editor. Same rules as a one-entry document."""
    parsed = parse_cve_feed(
        {"format": FEED_FORMAT, "version": FEED_VERSION, "entries": [payload]}
    )
    return parsed[0]


def _match(entry: FeedEntry, rule: str, package: str) -> MatchedBy | None:
    has_rule = bool(entry.requirement_id)
    has_package = bool(entry.profile_name)
    rule_ok = has_rule and entry.requirement_id == rule
    package_ok = has_package and bool(package) and entry.profile_name == package
    if has_rule and has_package:
        return "rule_and_package" if rule_ok and package_ok else None
    if has_rule:
        return "rule" if rule_ok else None
    if has_package:
        return "package" if package_ok else None
    return None


def references_for_check(
    entries: list[FeedEntry],
    *,
    status: str,
    rule_tech_name: str,
    profile_name: str | None,
) -> list[CveReference]:
    """CVE notes for one check. PASS and every other status get an empty list."""
    if str(status).strip().lower() != "fail":
        return []
    if not entries:
        return []
    rule = rule_tech_name.strip()
    package = (profile_name or "").strip()
    found: dict[str, CveReference] = {}
    for entry in entries:
        matched_by = _match(entry, rule, package)
        if matched_by is None:
            continue
        candidate = CveReference(cve_id=entry.cve_id, summary=entry.summary, matched_by=matched_by)
        current = found.get(entry.cve_id)
        if current is None or _SPECIFICITY[matched_by] > _SPECIFICITY[current.matched_by]:
            found[entry.cve_id] = candidate
    return [found[cve_id] for cve_id in sorted(found)]


def _as_feed_entry(row: CveFeedEntry) -> FeedEntry:
    return FeedEntry(
        cve_id=row.cve_id,
        requirement_id=row.requirement_id or "",
        profile_name=row.profile_name or "",
        summary=row.summary,
    )


async def load_feed_entries(db: AsyncSession) -> list[FeedEntry]:
    result = await db.execute(select(CveFeedEntry))
    return [_as_feed_entry(row) for row in result.scalars().all()]


async def feed_status(db: AsyncSession) -> CveFeedStatus:
    result = await db.execute(
        select(CveFeedEntry).order_by(
            CveFeedEntry.cve_id,
            CveFeedEntry.requirement_id,
            CveFeedEntry.profile_name,
        )
    )
    rows = list(result.scalars().all())
    imported_at = max((row.imported_at for row in rows), default=None)
    return CveFeedStatus(
        loaded=bool(rows),
        entry_count=len(rows),
        imported_at=imported_at,
        entries=tuple(
            StoredFeedEntry(
                id=row.id,
                cve_id=row.cve_id,
                requirement_id=row.requirement_id or "",
                profile_name=row.profile_name or "",
                summary=row.summary,
            )
            for row in rows
        ),
    )


def _same_target(entry: FeedEntry, *, exclude_id: int | None = None):
    stmt = select(CveFeedEntry.id).where(
        CveFeedEntry.cve_id == entry.cve_id,
        CveFeedEntry.requirement_id == entry.requirement_id,
        CveFeedEntry.profile_name == entry.profile_name,
    )
    if exclude_id is not None:
        stmt = stmt.where(CveFeedEntry.id != exclude_id)
    return stmt


async def add_feed_entry(db: AsyncSession, entry: FeedEntry) -> None:
    count = len((await db.execute(select(CveFeedEntry.id))).scalars().all())
    if count >= MAX_ENTRIES:
        raise CveFeedError(f"CVE feed has more than {MAX_ENTRIES} entries")
    if (await db.execute(_same_target(entry))).first() is not None:
        raise CveFeedError("This CVE is already listed for the same rule and profile")
    db.add(
        CveFeedEntry(
            cve_id=entry.cve_id,
            requirement_id=entry.requirement_id,
            profile_name=entry.profile_name,
            summary=entry.summary,
        )
    )
    await db.flush()


async def update_feed_entry(db: AsyncSession, entry_id: int, entry: FeedEntry) -> None:
    row = await db.get(CveFeedEntry, entry_id)
    if row is None:
        raise CveFeedMissing("CVE feed entry was not found")
    if (await db.execute(_same_target(entry, exclude_id=entry_id))).first() is not None:
        raise CveFeedError("This CVE is already listed for the same rule and profile")
    row.cve_id = entry.cve_id
    row.requirement_id = entry.requirement_id
    row.profile_name = entry.profile_name
    row.summary = entry.summary
    await db.flush()


async def delete_feed_entry(db: AsyncSession, entry_id: int) -> None:
    row = await db.get(CveFeedEntry, entry_id)
    if row is None:
        raise CveFeedMissing("CVE feed entry was not found")
    await db.delete(row)
    await db.flush()


async def replace_feed(db: AsyncSession, entries: list[FeedEntry]) -> None:
    await db.execute(delete(CveFeedEntry))
    for entry in entries:
        db.add(
            CveFeedEntry(
                cve_id=entry.cve_id,
                requirement_id=entry.requirement_id,
                profile_name=entry.profile_name,
                summary=entry.summary,
            )
        )
    await db.flush()
