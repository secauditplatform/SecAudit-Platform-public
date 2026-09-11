"""Scheduled import of profile packages from the mounted catalog."""

from __future__ import annotations

import logging
from pathlib import Path

from sqlalchemy import delete, select
from sqlalchemy.orm import Session, selectinload

from secaudit_core.enums import ScriptKind
from secaudit_core.models import Category, CheckScript, InterpreterRule, Rule, Profile
from secaudit_core.settings import SecAuditSettings
from secaudit_core.profile_packages import (
    DEFAULT_PROFILE_VERSION,
    load_profile_package,
    load_profile_rules_metadata,
    map_execution_type,
    profile_name_from_meta,
)
from secaudit_core.profile_resync import (
    capture_remediation_script_links,
    detach_remediation_script_links,
    delete_profile_rules_and_scripts,
    restore_remediation_script_links,
)
from secaudit_core.profiles_catalog import (
    build_catalog_sync,
    extract_os_metadata,
    infer_profile_family,
    normalize_profile_family,
)

logger = logging.getLogger(__name__)

DEFAULT_SYNC_FAMILIES = frozenset({"custom"})


def _storage_root(settings: SecAuditSettings) -> Path:
    root = Path(settings.profiles_storage_path)
    root.mkdir(parents=True, exist_ok=True)
    return root


def _persist_package(settings: SecAuditSettings, source: Path, profile_name: str) -> Path:
    from secaudit_core.package_paths import (
        normalize_shell_scripts_in_tree,
        replace_package_tree,
    )

    dest = replace_package_tree(source, _storage_root(settings) / profile_name)
    normalize_shell_scripts_in_tree(dest)
    return dest


def _resolve_category(db: Session, category_slug: str | None) -> Category:
    if not category_slug:
        raise ValueError("Could not determine profile category")

    category = db.execute(select(Category).where(Category.slug == category_slug)).scalar_one_or_none()
    if not category:
        raise ValueError(f"Category not found for slug '{category_slug}'")
    return category


def _persist_rule_rows(db: Session, profile: Profile, package_dir: Path) -> None:
    seen: set[str] = set()
    for meta in load_profile_rules_metadata(package_dir):
        base = str(meta.get("requirement_id") or meta.get("tech_name") or "").strip()
        if not base:
            continue
        tech_name = base[:64]
        if tech_name in seen:
            suffix = 2
            while True:
                candidate = f"{base[:60]}_{suffix}"[:64]
                if candidate not in seen:
                    tech_name = candidate
                    break
                suffix += 1
        seen.add(tech_name)
        title = meta.get("title") or meta.get("summary") or None
        if isinstance(title, str):
            title = title.strip()[:512] or None
        db.add(
            Rule(
                profile_id=profile.id,
                tech_name=tech_name,
                title=title,
                description=meta.get("explanation") or meta.get("description"),
                severity=meta.get("criticality") or meta.get("severity") or meta.get("impact") or meta.get("risk"),
                scap_rule_id=meta.get("scap_rule_id"),
            )
        )


def import_package_from_mount(
    db: Session,
    settings: SecAuditSettings,
    package_dir: Path,
    *,
    replace_existing: bool = False,
) -> Profile:
    """Copy a mounted package into persistent storage and register it in the database."""
    package = load_profile_package(package_dir)
    meta = package["profile"]
    scripts = package["scripts"]
    remediation_scripts = package.get("remediation_scripts", [])
    category_slug = meta.get("category_slug") or package.get("category_slug")
    category = _resolve_category(db, category_slug)
    resolved_format = meta.get("source_format") or "custom"
    if resolved_format not in {"custom", "xccdf", "oval"}:
        resolved_format = "custom"

    from secaudit_core.profile_packages import profile_overview_from_meta, profile_purpose_from_meta

    summary = profile_overview_from_meta(meta)
    detail = profile_purpose_from_meta(meta)
    name = profile_name_from_meta(meta)
    if not name:
        raise ValueError("Profile description is missing profile_name")
    profile_family = normalize_profile_family(
        meta.get("profile_family") or infer_profile_family(
            name,
            summary,
            detail,
            meta.get("benchmark_ref"),
        )
    )
    raw_ref = meta.get("benchmark_ref")
    benchmark_ref = str(raw_ref).strip() if isinstance(raw_ref, str) and raw_ref.strip() else None
    os_fields = extract_os_metadata(meta)

    existing = db.execute(
        select(Profile)
        .options(selectinload(Profile.check_scripts))
        .where(Profile.profile_name == name)
    ).scalar_one_or_none()
    if existing and not replace_existing:
        raise ValueError(f"Profile '{name}' already imported")

    stored_path = _persist_package(settings, package_dir, name)
    from secaudit_core.profile_packages import ensure_compliance_playbook_declared

    ensure_compliance_playbook_declared(stored_path)
    job_script_files: dict[int, str] = {}
    if existing is None:
        profile = Profile(
            profile_name=name,
            version=meta.get("version", DEFAULT_PROFILE_VERSION),
            summary=summary,
            category_id=category.id,
            package_path=str(stored_path),
            source_format=resolved_format,
            profile_family=profile_family,
            scap_profile_id=meta.get("scap_profile_id"),
            profile_title=meta.get("profile_title"),
            benchmark_ref=benchmark_ref,
            os_name=os_fields["os_name"],
            os_version=os_fields["os_version"],
            os_vendor=os_fields["os_vendor"],
            is_active=meta.get("is_active", True),
        )
        db.add(profile)
        db.flush()
    else:
        profile = existing
        profile.profile_name = name
        profile.version = meta.get("version", DEFAULT_PROFILE_VERSION)
        profile.summary = summary
        profile.category_id = category.id
        profile.package_path = str(stored_path)
        profile.source_format = resolved_format
        profile.profile_family = profile_family
        profile.scap_profile_id = meta.get("scap_profile_id")
        profile.profile_title = meta.get("profile_title")
        profile.benchmark_ref = benchmark_ref
        profile.os_name = os_fields["os_name"]
        profile.os_version = os_fields["os_version"]
        profile.os_vendor = os_fields["os_vendor"]
        profile.is_active = meta.get("is_active", True)
        job_script_files = capture_remediation_script_links(db, profile.id)
        detach_remediation_script_links(db, profile.id)
        delete_profile_rules_and_scripts(db, profile.id)
        db.flush()

    _persist_rule_rows(db, profile, package_dir)

    for item in scripts:
        script = CheckScript(
            profile_id=profile.id,
            name=item["name"],
            execution_type=map_execution_type(item.get("type", "SSH")),
            script_file=item["script_file"],
            script_kind=ScriptKind.AUDIT,
            description=item.get("description"),
        )
        db.add(script)
        db.flush()

        for rule in item.get("context", []):
            tech_name = rule.get("techName") or rule.get("tech_name")
            if not tech_name:
                continue
            db.add(
                InterpreterRule(
                    check_script_id=script.id,
                    regex=rule["regex"],
                    extraction_type=rule.get("extractionType", "SINGLE"),
                    tech_name=tech_name,
                )
            )

    for item in remediation_scripts:
        script_path = package_dir / item["script_file"]
        if not script_path.is_file():
            raise FileNotFoundError(f"Remediation script not found: {item['script_file']}")
        db.add(
            CheckScript(
                profile_id=profile.id,
                name=item["name"],
                execution_type=map_execution_type(item.get("type", "SSH")),
                script_file=item["script_file"],
                script_kind=ScriptKind.REMEDIATION,
                description=item.get("description"),
            )
        )

    if job_script_files:
        restore_remediation_script_links(db, profile.id, job_script_files)

    from secaudit_core.compliance_playbooks import upsert_compliance_playbook_for_profile

    upsert_compliance_playbook_for_profile(db, profile, package_dir=stored_path)

    db.flush()
    return profile


def summarize_catalog_sync_queue(
    db: Session,
    profiles_path: str,
    *,
    families: frozenset[str] | None = None,
) -> dict[str, int]:
    """Count custom profiles waiting for scheduled import or update."""
    allowed = families or DEFAULT_SYNC_FAMILIES
    catalog = build_catalog_sync(db, profiles_path)
    targets = [entry for entry in catalog if entry.get("profile_family") in allowed]

    latest_by_name: dict[str, dict] = {}
    for entry in targets:
        if entry.get("is_latest"):
            latest_by_name[entry["profile_name"]] = entry

    pending_imports = 0
    pending_updates = 0
    for entry in latest_by_name.values():
        if entry.get("imported_version") is None:
            pending_imports += 1
        elif entry.get("update_available"):
            pending_updates += 1

    return {
        "pending_imports": pending_imports,
        "pending_updates": pending_updates,
    }


def sync_profiles_catalog(
    db: Session,
    settings: SecAuditSettings,
    *,
    families: frozenset[str] | None = None,
    update_existing: bool = True,
) -> dict:
    """Import new custom packages from mount; refresh when version or package layout changes."""
    root = Path(settings.profiles_path)
    if not root.exists():
        return {
            "imported": [],
            "updated": [],
            "skipped": [],
            "errors": [],
            "count": 0,
        }

    allowed = families or DEFAULT_SYNC_FAMILIES
    catalog = build_catalog_sync(db, settings.profiles_path)
    targets = [entry for entry in catalog if entry.get("profile_family") in allowed]

    latest_by_name: dict[str, dict] = {}
    for entry in targets:
        if entry.get("is_latest"):
            latest_by_name[entry["profile_name"]] = entry

    imported: list[str] = []
    updated: list[str] = []
    skipped: list[str] = []
    errors: list[dict[str, str]] = []

    for entry in latest_by_name.values():
        package_path = entry["package_path"]
        name_known = entry.get("imported_version") is not None
        should_import_new = not name_known
        # update_available covers newer version and content/layout drift (renamed scripts, etc.)
        should_update = (
            update_existing
            and name_known
            and entry.get("update_available")
            and entry.get("is_latest")
        )

        if should_import_new:
            try:
                with db.begin_nested():
                    import_package_from_mount(db, settings, Path(package_path))
                imported.append(package_path)
                logger.info("Catalog sync imported %s", package_path)
            except Exception as exc:
                logger.warning("Catalog sync failed to import %s: %s", package_path, exc)
                errors.append({"package_path": package_path, "message": str(exc)})
            continue

        if should_update:
            try:
                with db.begin_nested():
                    import_package_from_mount(
                        db,
                        settings,
                        Path(package_path),
                        replace_existing=True,
                    )
                updated.append(package_path)
                logger.info("Catalog sync updated %s", package_path)
            except Exception as exc:
                logger.warning("Catalog sync failed to update %s: %s", package_path, exc)
                errors.append({"package_path": package_path, "message": str(exc)})
            continue

        skipped.append(package_path)

    from secaudit_core.compliance_playbooks import dedupe_orphaned_compliance_templates

    dedupe_orphaned_compliance_templates(db)

    return {
        "imported": imported,
        "updated": updated,
        "skipped": skipped,
        "errors": errors,
        "count": len(imported) + len(updated),
    }
