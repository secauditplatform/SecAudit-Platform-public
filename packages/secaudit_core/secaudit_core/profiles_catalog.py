"""Bundled profile catalog — scans the mounted profiles source tree."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from secaudit_core.models import Profile
from secaudit_core.profile_packages import (
    DESCRIPTION_FILE,
    DEFAULT_PROFILE_VERSION,
    _find_profile_file,
    normalize_description_meta,
    package_is_catalog_candidate,
    profile_name_from_meta,
    profile_overview_from_meta,
    profile_purpose_from_meta,
)

PROFILE_FAMILIES = frozenset({"custom"})

EXCLUDED_PATH_FRAGMENTS = (
    "/src/test/",
    "/test/resources/",
    "/target/",
    "/node_modules/",
    "/backups/",
    "/profiles_backup_en/",
    "/profiles_backup_ru/",
)


def normalize_profile_family(value: str | None) -> str:
    """Collapse legacy family tags to the single supported value."""
    if value and str(value).strip().lower() == "custom":
        return "custom"
    return "custom"


def infer_profile_family(*texts: str | None) -> str:
    """All packages are treated as custom; texts are ignored for family tagging."""
    _ = texts
    return "custom"


def os_slug(name: str | None) -> str | None:
    if not name:
        return None
    slug = re.sub(r"[^a-z0-9]+", "-", str(name).lower()).strip("-")
    return slug or None


def extract_os_metadata(meta: dict) -> dict[str, str | None]:
    os_meta = meta.get("os") or {}
    if not isinstance(os_meta, dict):
        return {"os_name": None, "os_version": None, "os_vendor": None}
    version = os_meta.get("version")
    return {
        "os_name": os_meta.get("name"),
        "os_version": str(version) if version else None,
        "os_vendor": os_meta.get("vendor"),
    }


def infer_platform(category_slug: str) -> str:
    if category_slug == "windows-platform":
        return "windows"
    if category_slug == "network-platform":
        return "network"
    return "linux"


def extract_benchmark_ref(*texts: str | None) -> str | None:
    """Legacy helper kept for callers; trademark pattern scraping removed."""
    _ = texts
    return None


def _load_profile_meta(profile_file: Path) -> dict:
    try:
        return normalize_description_meta(json.loads(profile_file.read_text(encoding="utf-8-sig")))
    except (OSError, json.JSONDecodeError):
        return {}


def _is_excluded_catalog_path(package_dir: Path) -> bool:
    posix = package_dir.as_posix().lower()
    return any(fragment in posix for fragment in EXCLUDED_PATH_FRAGMENTS)


def _version_sort_key(version: str | None) -> tuple[int, ...]:
    parts: list[int] = []
    for piece in re.split(r"[.\-_]", str(version or "0")):
        if piece.isdigit():
            parts.append(int(piece))
        elif piece:
            parts.append(0)
    return tuple(parts or (0,))


def _package_rank(package_dir: Path, meta: dict) -> tuple:
    """Higher tuple values win when deduplicating packages with the same profile_name+version."""
    path = package_dir.as_posix().lower()
    score = 0
    if "_ai" in path or "_cre_ai" in path:
        score += 100
    if any(tag in path for tag in ("_gke", "_deckhouse", "_pci", "_ubrir", "_fstek")):
        score += 30
    if "/source/" in path:
        score -= 40
    version_key = _version_sort_key(meta.get("version"))
    depth = path.count("/")
    return (score, version_key, -depth)


def infer_category_slug_quick(package_dir: Path, meta: dict | None = None) -> str:
    """Infer category from metadata or path without reading extra package files."""
    if meta and meta.get("category_slug"):
        return str(meta["category_slug"])

    path = package_dir.as_posix().lower()
    if "windows" in path:
        return "windows-platform"
    if "network" in path or "cisco" in path or "juniper" in path:
        return "network-platform"
    if any(token in path for token in ("operating system", "operating systems", "/os/", "linux", "rhel", "ubuntu", "centos", "debian")):
        return "linux-platform"
    return "services"


def discover_importable_package_dirs(root: Path) -> list[Path]:
    """Return unique package roots (deduped by profile_name+version, preferring _AI packages)."""
    return list(iter_importable_package_dirs(root))


def _iter_raw_importable_package_dirs(root: Path):
    """Yield every structurally valid package root (may include legacy/_AI duplicates)."""
    if not root.exists():
        return

    seen_dirs: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            name
            for name in dirnames
            if not _is_excluded_catalog_path(Path(dirpath) / name)
            and name.lower() not in {"node_modules", "target", ".git"}
        ]

        profile_names = [
            name
            for name in filenames
            if name == DESCRIPTION_FILE
        ]
        if not profile_names:
            continue

        package_dir = Path(dirpath)
        package_path = str(package_dir)
        if package_path in seen_dirs or _is_excluded_catalog_path(package_dir):
            continue
        seen_dirs.add(package_path)

        profile_file = _find_profile_file(package_dir)
        if profile_file is None or profile_file.name not in profile_names:
            continue

        if not package_is_catalog_candidate(package_dir):
            continue

        yield package_dir


def iter_importable_package_dirs(root: Path):
    """Yield unique package roots, keeping the best copy per profile_name+version."""
    best: dict[tuple[str, str], tuple[tuple, Path]] = {}

    for package_dir in _iter_raw_importable_package_dirs(root):
        profile_file = _find_profile_file(package_dir)
        if not profile_file:
            continue
        meta = _load_profile_meta(profile_file)
        name = profile_name_from_meta(meta) or package_dir.name
        version = str(meta.get("version") or DEFAULT_PROFILE_VERSION)
        key = (name, version)
        rank = _package_rank(package_dir, meta)
        current = best.get(key)
        if current is None or rank > current[0]:
            best[key] = (rank, package_dir)

    for _rank, package_dir in sorted(best.values(), key=lambda item: str(item[1])):
        yield package_dir


def _build_catalog_entry(
    package_dir: Path,
    *,
    imported_map: dict[str, int],
    family: str | None,
) -> dict | None:
    profile_file = _find_profile_file(package_dir)
    if not profile_file:
        return None

    meta = _load_profile_meta(profile_file)
    name = profile_name_from_meta(meta) or package_dir.name
    summary = profile_overview_from_meta(meta)
    detail = profile_purpose_from_meta(meta)
    raw_ref = meta.get("benchmark_ref")
    benchmark_ref = str(raw_ref).strip() if isinstance(raw_ref, str) and raw_ref.strip() else None
    profile_family = normalize_profile_family(
        meta.get("profile_family") or infer_profile_family(name, summary, detail, benchmark_ref)
    )
    if family and profile_family != family:
        return None

    category_slug = meta.get("category_slug") or infer_category_slug_quick(package_dir, meta)
    os_fields = extract_os_metadata(meta)
    return {
        "package_path": str(package_dir),
        "profile_name": name,
        "version": meta.get("version", DEFAULT_PROFILE_VERSION),
        "summary": summary,
        "profile_family": profile_family,
        "category_slug": category_slug,
        "benchmark_ref": benchmark_ref,
        "platform": infer_platform(category_slug),
        "os_name": os_fields["os_name"],
        "os_version": os_fields["os_version"],
        "os_vendor": os_fields["os_vendor"],
        "imported": name in imported_map,
        "profile_id": imported_map.get(name),
    }


def _enrich_catalog_entries(entries: list[dict]) -> list[dict]:
    newest_by_name: dict[str, tuple[int, ...]] = {}
    for item in entries:
        key = _version_sort_key(item.get("version"))
        if item["profile_name"] not in newest_by_name or key > newest_by_name[item["profile_name"]]:
            newest_by_name[item["profile_name"]] = key

    for item in entries:
        item["is_latest"] = _version_sort_key(item.get("version")) == newest_by_name[item["profile_name"]]
        imported_version = item.get("imported_version")
        version_update = bool(
            imported_version
            and _version_sort_key(item.get("version")) != _version_sort_key(imported_version)
        )
        content_stale = bool(item.get("content_stale"))
        item["update_available"] = version_update or content_stale

    entries.sort(
        key=lambda item: (item["profile_family"], item["profile_name"].lower(), item["version"])
    )
    return entries


def iter_catalog_entries_from_imports(
    profiles_path: str,
    *,
    imported_rows: list[tuple],
    family: str | None = None,
):
    """Yield catalog entries using a preloaded list of imported profile rows.

    Each row is ``(profile_name, version, id)`` or
    ``(profile_name, version, id, package_path)``.
    """
    root = Path(profiles_path)
    if not root.exists():
        return

    imported_map: dict[tuple[str, str], int] = {}
    imported_by_name: dict[str, tuple[str, int, str | None]] = {}
    for row in imported_rows:
        if len(row) >= 4:
            profile_name, version, sid, package_path = row[0], row[1], row[2], row[3]
        else:
            profile_name, version, sid = row[0], row[1], row[2]
            package_path = None
        imported_map[(profile_name, version)] = sid
        imported_by_name[profile_name] = (version, sid, package_path)

    name_id_map = {name: sid for (name, _ver), sid in imported_map.items()}

    from secaudit_core.profile_packages import package_structure_signature

    for package_dir in iter_importable_package_dirs(root):
        entry = _build_catalog_entry(
            package_dir,
            imported_map=name_id_map,
            family=family,
        )
        if not entry:
            continue
        imported_exact_id = imported_map.get((entry["profile_name"], entry["version"]))
        imported_for_name = imported_by_name.get(entry["profile_name"])
        entry["imported"] = imported_exact_id is not None
        entry["profile_id"] = imported_exact_id or (imported_for_name[1] if imported_for_name else None)
        entry["imported_version"] = imported_for_name[0] if imported_for_name else None
        entry["is_latest"] = True
        content_stale = False
        if imported_for_name and imported_for_name[2]:
            stored = Path(imported_for_name[2])
            if stored.is_dir():
                content_stale = package_structure_signature(package_dir) != package_structure_signature(
                    stored
                )
            else:
                content_stale = True
        entry["content_stale"] = content_stale
        entry["update_available"] = bool(
            (
                entry["imported_version"]
                and _version_sort_key(entry.get("version"))
                != _version_sort_key(entry["imported_version"])
            )
            or content_stale
        )
        yield entry


def iter_catalog_entries_sync(
    db: Session,
    profiles_path: str,
    *,
    family: str | None = None,
):
    """Yield catalog entries as packages are discovered on the mount."""
    result = db.execute(
        select(Profile.profile_name, Profile.version, Profile.id, Profile.package_path)
    )
    rows = [
        (row.profile_name, row.version, row.id, row.package_path) for row in result.all()
    ]
    yield from iter_catalog_entries_from_imports(
        profiles_path,
        imported_rows=rows,
        family=family,
    )


def build_catalog_sync(
    db: Session,
    profiles_path: str,
    *,
    family: str | None = None,
) -> list[dict]:
    """Return bundled profile entries from the mounted profiles tree with import status."""
    entries = list(iter_catalog_entries_sync(db, profiles_path, family=family))
    return _enrich_catalog_entries(entries)
