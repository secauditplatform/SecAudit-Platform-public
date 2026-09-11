"""Bundled profile catalog — scans the mounted profiles source tree."""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from secaudit_core.profiles_catalog import (
    PROFILE_FAMILIES,
    build_catalog_sync,
    discover_importable_package_dirs,
    extract_benchmark_ref,
    extract_os_metadata,
    infer_platform,
    infer_profile_family,
    normalize_profile_family,
    os_slug,
)

__all__ = [
    "PROFILE_FAMILIES",
    "build_catalog",
    "discover_importable_package_dirs",
    "extract_benchmark_ref",
    "extract_os_metadata",
    "infer_platform",
    "infer_profile_family",
    "normalize_profile_family",
    "os_slug",
]


async def build_catalog(db: AsyncSession, *, family: str | None = None) -> list[dict]:
    """Return bundled profile entries from the mounted profiles tree with import status."""

    def _run(sync_session):
        return build_catalog_sync(sync_session, settings.profiles_path, family=family)

    return await db.run_sync(_run)
