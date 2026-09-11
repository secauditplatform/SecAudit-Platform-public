"""Register optional package compliance playbooks as Playbook DB rows."""

from __future__ import annotations

import re
from pathlib import Path

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from secaudit_core.enums import JobScope, PlaybookKind
from secaudit_core.models import Category, Job, Playbook, Profile
from secaudit_core.profile_packages import (
    ensure_compliance_playbook_declared,
    read_compliance_playbook,
)
from secaudit_core.profiles_catalog import infer_platform

_COMPLIANCE_SUFFIX_RE = re.compile(r"\s*[—–-]\s*Compliance\s*$|\s+Compliance\s*$", re.IGNORECASE)
# Profile packages may mix Latin/Cyrillic profile_name city spellings.
_CYR_TO_LATIN = (
    ("воронеж", "voronezh"),
    ("орёл", "orel"),
    ("орел", "orel"),
    ("смоленск", "smolensk"),
)


def compliance_template_name(profile: Profile) -> str:
    name = (profile.profile_name or "Profile").strip()
    return f"{name} — Compliance"


def normalize_compliance_template_key(*parts: str | None) -> str:
    """Stable key for matching renamed/orphaned compliance templates."""
    source = next((str(part).strip() for part in parts if str(part or "").strip()), "")
    cleaned = _COMPLIANCE_SUFFIX_RE.sub("", source).strip()
    folded = " ".join(cleaned.casefold().split())
    for cyrillic, latin in _CYR_TO_LATIN:
        folded = folded.replace(cyrillic, latin)
    return folded


def template_match_keys(*parts: str | None) -> set[str]:
    return {key for part in parts if (key := normalize_compliance_template_key(part))}


def _platform_for_profile(db: Session, profile: Profile) -> str:
    if profile.category_id is None:
        return "linux"
    category = db.get(Category, profile.category_id)
    if category is None:
        return "linux"
    return infer_platform(category.slug)


def _find_existing_template(db: Session, profile: Profile, desired_name: str) -> Playbook | None:
    existing = db.execute(
        select(Playbook).where(
            Playbook.kind == PlaybookKind.COMPLIANCE_TEMPLATE,
            Playbook.profile_id == profile.id,
        )
    ).scalar_one_or_none()
    if existing is not None:
        return existing

    by_name = db.execute(select(Playbook).where(Playbook.name == desired_name)).scalar_one_or_none()
    if by_name is not None and by_name.kind == PlaybookKind.COMPLIANCE_TEMPLATE:
        if by_name.profile_id in {None, profile.id}:
            return by_name

    desired_keys = template_match_keys(desired_name, profile.profile_name)
    if not desired_keys:
        return None
    candidates = db.execute(
        select(Playbook).where(
            Playbook.kind == PlaybookKind.COMPLIANCE_TEMPLATE,
            Playbook.profile_id.is_(None),
        )
    ).scalars().all()
    matches = [
        row
        for row in candidates
        if normalize_compliance_template_key(row.name) in desired_keys
    ]
    if not matches:
        return None
    return min(matches, key=lambda row: row.id)


def _detach_jobs_and_delete(db: Session, playbook: Playbook) -> None:
    db.execute(update(Job).where(Job.playbook_id == playbook.id).values(playbook_id=None))
    db.delete(playbook)


def _group_root(parent: dict[str, str], key: str) -> str:
    parent.setdefault(key, key)
    while parent[key] != key:
        parent[key] = parent[parent[key]]
        key = parent[key]
    return key


def _union_keys(parent: dict[str, str], keys: set[str]) -> None:
    if not keys:
        return
    iterator = iter(keys)
    root = _group_root(parent, next(iterator))
    for key in iterator:
        other = _group_root(parent, key)
        if other != root:
            parent[other] = root


def dedupe_orphaned_compliance_templates(db: Session) -> int:
    """Drop leftover templates after a profile was re-imported under a new profile_name."""
    rows = db.execute(
        select(Playbook, Profile.profile_name)
        .outerjoin(Profile, Playbook.profile_id == Profile.id)
        .where(Playbook.kind == PlaybookKind.COMPLIANCE_TEMPLATE)
    ).all()

    parent: dict[str, str] = {}
    membership: list[tuple[Playbook, set[str]]] = []
    for playbook, profile_name in rows:
        keys = template_match_keys(profile_name, playbook.name)
        if not keys:
            continue
        _union_keys(parent, keys)
        membership.append((playbook, keys))

    grouped: dict[str, list[Playbook]] = {}
    for playbook, keys in membership:
        root = _group_root(parent, next(iter(keys)))
        grouped.setdefault(root, []).append(playbook)

    removed = 0
    for items in grouped.values():
        linked = [item for item in items if item.profile_id is not None]
        orphans = [item for item in items if item.profile_id is None]
        keep_profile_ids: set[int] = set()
        extras: list[Playbook] = []
        for item in sorted(linked, key=lambda row: row.id):
            profile_id = item.profile_id
            if profile_id is None:
                continue
            if profile_id in keep_profile_ids:
                extras.append(item)
            else:
                keep_profile_ids.add(profile_id)
        if linked:
            extras.extend(orphans)
        for extra in extras:
            _detach_jobs_and_delete(db, extra)
            removed += 1
    if removed:
        db.flush()
    return removed


def upsert_compliance_playbook_for_profile(
    db: Session,
    profile: Profile,
    *,
    package_dir: Path | None = None,
) -> Playbook | None:
    """Create/update Playbook(kind=compliance_template) from package compliance YAML."""
    root = Path(package_dir) if package_dir is not None else None
    if root is None:
        if not profile.package_path:
            return None
        root = Path(profile.package_path)
    if not root.is_dir():
        return None

    # Ensure convention files are declared in description.json before read.
    ensure_compliance_playbook_declared(root)
    payload = read_compliance_playbook(root)
    if payload is None:
        return None

    platform = _platform_for_profile(db, profile)
    scope = JobScope.NETWORK if platform == "network" else JobScope.STANDARD
    desired_name = compliance_template_name(profile)
    description = (
        f"Compliance Ansible template from profile '{profile.profile_name}' "
        f"({payload['file']})"
    )

    existing = _find_existing_template(db, profile, desired_name)

    if existing is None:
        name_conflict = db.execute(
            select(Playbook.id).where(Playbook.name == desired_name)
        ).scalar_one_or_none()
        name = desired_name if name_conflict is None else f"{profile.profile_name} Compliance"
        playbook = Playbook(
            name=name,
            description=description,
            content=payload["content"],
            is_active=True,
            kind=PlaybookKind.COMPLIANCE_TEMPLATE,
            profile_id=profile.id,
            version=payload["version"],
            scope=scope,
            platform=platform,
            owner_sub=None,
        )
        db.add(playbook)
        db.flush()
        dedupe_orphaned_compliance_templates(db)
        return playbook

    # Keep stable unique name when possible; refresh content/version from package.
    if existing.name != desired_name:
        conflict = db.execute(
            select(Playbook.id).where(Playbook.name == desired_name, Playbook.id != existing.id)
        ).scalar_one_or_none()
        if conflict is None:
            existing.name = desired_name
    existing.description = description
    existing.content = payload["content"]
    existing.version = payload["version"]
    existing.scope = scope
    existing.platform = platform
    existing.is_active = True
    existing.kind = PlaybookKind.COMPLIANCE_TEMPLATE
    existing.profile_id = profile.id
    db.flush()
    dedupe_orphaned_compliance_templates(db)
    return existing
