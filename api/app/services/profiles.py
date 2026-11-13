import json
from pathlib import Path

from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.config import settings
from app.models import (
  Category,
  CategoryType,
  CheckResult,
  CheckScript,
  ComplianceWaiver,
  InterpreterRule,
  Job,
  JobRun,
  JobStatus,
  JobTemplate,
  Playbook,
  RemediationJob,
  RemediationResult,
  RemediationRun,
  Rule,
  ScheduledReport,
  ScriptKind,
  Profile,
  ProfileVersion,
  TaskOutbox,
)
from app.schemas import ProfileCreate, ProfileDeleteOptions, ProfileDependencies
from secaudit_core.enums import OutboxStatus
from secaudit_core.models import ScheduledReportDeliveryAttempt
from app.services.interpreter import (
  infer_category_from_package_dir,
  load_profile_package,
  load_profile_rules_metadata,
  load_rule_changelog,
  map_execution_type,
  materialize_uploaded_package,
  package_encoding_hint,
  profile_name_from_meta,
  DEFAULT_PROFILE_VERSION,
  read_package_text_file,
  update_profile_rule_in_package,
)
from secaudit_core.profile_packages import count_profile_rules_metadata
from app.services.scap import prepare_upload_package
from app.services.profiles_catalog import build_catalog, discover_importable_package_dirs
from secaudit_core.profiles_catalog import (
  build_catalog_sync,
  extract_os_metadata,
  infer_profile_family,
  normalize_profile_family,
  os_slug,
  _version_sort_key,
)
from secaudit_core.profiles_sync_status import load_catalog_sync_status
from secaudit_core.profile_resync import (
  capture_remediation_script_links,
  detach_remediation_script_links,
  restore_remediation_script_links,
)

MAX_SCRIPT_CONTENT_BYTES = 1_048_576


class ProfileDependencyError(ValueError):
  """Raised when a profile cannot be deleted without an explicit cascade."""

  def __init__(self, dependencies: ProfileDependencies, message: str | None = None):
    self.dependencies = dependencies
    self.code = "profile_has_dependencies"
    super().__init__(message or "Profile is referenced by dependent resources")


class ProfileActiveRunsError(ValueError):
  """Raised when cascade delete is blocked by pending/running job runs."""

  def __init__(self, dependencies: ProfileDependencies, message: str | None = None):
    self.dependencies = dependencies
    self.code = "profile_has_active_runs"
    super().__init__(message or "Stop all active runs before deleting the profile")


class ProfileVersionInUseError(ValueError):
  """Raised when a profile version cannot be deleted without reassigning jobs."""


class ProfileService:
  def _storage_root(self) -> Path:
    root = Path(settings.profiles_storage_path)
    root.mkdir(parents=True, exist_ok=True)
    return root

  def _catalog_root(self) -> Path:
    return Path(settings.profiles_path)

  def _assert_import_path_allowed(self, package_path: str | Path) -> Path:
    """Confine import/preview paths to catalog mount or storage root."""
    from secaudit_core.package_paths import assert_path_under_roots

    return assert_path_under_roots(
      package_path,
      self._catalog_root(),
      self._storage_root(),
      label="package_path",
    )

  def _persist_package(self, source: Path, profile_name: str) -> Path:
    from secaudit_core.package_paths import (
      normalize_shell_scripts_in_tree,
      replace_package_tree,
    )

    dest = replace_package_tree(source, self._storage_root() / profile_name)
    normalize_shell_scripts_in_tree(dest)
    return dest

  def _remove_stored_package(self, package_path: str | None) -> None:
    if not package_path:
      return
    pkg = Path(package_path)
    storage_root = self._storage_root().resolve()
    try:
      resolved = pkg.resolve()
    except OSError:
      return
    if resolved == storage_root or storage_root not in resolved.parents:
      return
    if resolved.exists():
      from secaudit_core.package_paths import remove_package_tree

      remove_package_tree(resolved)

  async def list_profiles(
    self,
    db: AsyncSession,
    *,
    category_id: int | None = None,
    os_name: str | None = None,
    os_version: str | None = None,
    os: str | None = None,
  ) -> list[Profile]:
    query = (
      select(Profile)
      .options(selectinload(Profile.category))
      .order_by(Profile.profile_name)
    )
    if category_id:
      query = query.where(Profile.category_id == category_id)
    if os_name:
      query = query.where(Profile.os_name.ilike(f"%{os_name}%"))
    if os_version:
      query = query.where(Profile.os_version.ilike(f"%{os_version}%"))
    if os:
      os_filter = os.strip().lower()
      result = await db.execute(query)
      profiles = list(result.scalars().all())
      return [
        profile
        for profile in profiles
        if os_slug(profile.os_name) == os_filter or (profile.os_name or "").lower() == os_filter
      ]
    result = await db.execute(query)
    return list(result.scalars().all())

  async def catalog_latest_versions(self, db: AsyncSession) -> dict[str, str]:
    """Map profile_name -> latest catalog package version on the mount."""
    def _run(sync_session):
      catalog = build_catalog_sync(sync_session, settings.profiles_path)
      latest: dict[str, tuple[tuple[int, ...], str]] = {}
      for entry in catalog:
        if not entry.get("is_latest"):
          continue
        key = _version_sort_key(entry.get("version"))
        current = latest.get(entry["profile_name"])
        if current is None or key > current[0]:
          latest[entry["profile_name"]] = (key, str(entry.get("version") or DEFAULT_PROFILE_VERSION))
      return {name: version for name, (_key, version) in latest.items()}

    return await db.run_sync(_run)

  async def list_profile_counts(
    self, db: AsyncSession, profiles: list[Profile]
  ) -> dict[int, dict[str, int]]:
    """Batch rules/script counts for list endpoints (avoids N+1 detail fetches)."""
    if not profiles:
      return {}
    profile_ids = [profile.id for profile in profiles]
    script_rows = (
      await db.execute(
        select(CheckScript.profile_id, CheckScript.script_kind, func.count())
        .where(CheckScript.profile_id.in_(profile_ids))
        .group_by(CheckScript.profile_id, CheckScript.script_kind)
      )
    ).all()
    audit: dict[int, int] = {pid: 0 for pid in profile_ids}
    remediation: dict[int, int] = {pid: 0 for pid in profile_ids}
    for profile_id, kind, count in script_rows:
      if kind == ScriptKind.REMEDIATION:
        remediation[profile_id] = int(count)
      else:
        audit[profile_id] = int(count)

    interp_rows = (
      await db.execute(
        select(CheckScript.profile_id, func.count(InterpreterRule.id))
        .join(InterpreterRule, InterpreterRule.check_script_id == CheckScript.id)
        .where(CheckScript.profile_id.in_(profile_ids))
        .group_by(CheckScript.profile_id)
      )
    ).all()
    interp_counts = {profile_id: int(count) for profile_id, count in interp_rows}

    counts: dict[int, dict[str, int]] = {}
    for profile in profiles:
      rules_count = 0
      if profile.package_path:
        package_dir = Path(profile.package_path)
        if package_dir.is_dir():
          rules_count = count_profile_rules_metadata(package_dir)
      if not rules_count:
        rules_count = interp_counts.get(profile.id, 0)
      counts[profile.id] = {
        "rules_count": rules_count,
        "audit_scripts_count": audit.get(profile.id, 0),
        "remediation_scripts_count": remediation.get(profile.id, 0),
      }
    return counts

  def enrich_profile_read(
    self,
    profile: Profile,
    latest_versions: dict[str, str] | None = None,
    *,
    counts: dict[str, int] | None = None,
  ) -> dict:
    payload = {
      "id": profile.id,
      "profile_name": profile.profile_name,
      "version": profile.version,
      "summary": profile.summary,
      "category_id": profile.category_id,
      "category_name": profile.category.name if profile.category else None,
      "package_path": profile.package_path,
      "source_format": profile.source_format,
      "profile_family": profile.profile_family,
      "scap_profile_id": profile.scap_profile_id,
      "profile_title": profile.profile_title,
      "benchmark_ref": profile.benchmark_ref,
      "os_name": profile.os_name,
      "os_version": profile.os_version,
      "os_vendor": profile.os_vendor,
      "is_active": profile.is_active,
      "created_at": profile.created_at,
      "package_version": None,
      "needs_update": False,
      "rules_count": 0,
      "audit_scripts_count": 0,
      "remediation_scripts_count": 0,
    }
    if counts:
      payload["rules_count"] = int(counts.get("rules_count", 0))
      payload["audit_scripts_count"] = int(counts.get("audit_scripts_count", 0))
      payload["remediation_scripts_count"] = int(counts.get("remediation_scripts_count", 0))
    if latest_versions and profile.profile_name in latest_versions:
      latest = latest_versions[profile.profile_name]
      payload["package_version"] = latest
      payload["needs_update"] = _version_sort_key(latest) != _version_sort_key(profile.version)
    return payload

  def _resolve_script_path(self, package_path: str, script_file: str) -> Path:
    package_dir = Path(package_path).resolve()
    if not package_dir.is_dir():
      raise FileNotFoundError("Profile package directory not found")

    script_path = (package_dir / script_file).resolve()
    if script_path != package_dir and package_dir not in script_path.parents:
      raise ValueError("Invalid script path")

    return script_path

  def _read_script_content(self, package_path: str, script_file: str) -> str:
    script_path = self._resolve_script_path(package_path, script_file)
    if not script_path.is_file():
      raise FileNotFoundError(f"Script file not found: {script_file}")

    encoding_hint = None
    package_dir = Path(package_path)
    if package_dir.is_dir():
      encoding_hint = package_encoding_hint(package_dir)

    return read_package_text_file(script_path, encoding_hint=encoding_hint)

  async def _get_script_record(
    self,
    db: AsyncSession,
    profile_id: int,
    script_id: int,
  ) -> tuple[Profile, CheckScript]:
    profile = await self.get_profile(db, profile_id)
    if not profile:
      raise LookupError("Profile not found")

    script = next((item for item in profile.check_scripts if item.id == script_id), None)
    if not script:
      raise LookupError("Check script not found")

    return profile, script

  async def get_check_script_content(
    self,
    db: AsyncSession,
    profile_id: int,
    script_id: int,
  ) -> dict[str, str]:
    profile, script = await self._get_script_record(db, profile_id, script_id)

    if not profile.package_path:
      raise FileNotFoundError("Profile package path not set")

    content = self._read_script_content(profile.package_path, script.script_file)

    return {
      "script_file": script.script_file,
      "content": content,
    }

  async def update_check_script_content(
    self,
    db: AsyncSession,
    profile_id: int,
    script_id: int,
    content: str,
  ) -> dict[str, str]:
    profile, script = await self._get_script_record(db, profile_id, script_id)

    if not profile.package_path:
      raise FileNotFoundError("Profile package path not set")

    script_path = self._resolve_script_path(profile.package_path, script.script_file)
    if not script_path.is_file():
      raise FileNotFoundError(f"Script file not found: {script.script_file}")

    from secaudit_core.package_paths import normalize_text_newlines

    content = normalize_text_newlines(content)
    encoded = content.encode("utf-8")
    if len(encoded) > MAX_SCRIPT_CONTENT_BYTES:
      raise ValueError(f"Script content exceeds maximum size of {MAX_SCRIPT_CONTENT_BYTES} bytes")

    script_path.write_text(content, encoding="utf-8", newline="\n")

    return {
      "script_file": script.script_file,
      "content": content,
    }

  async def add_check_scripts(
    self,
    db: AsyncSession,
    profile_id: int,
    kind: ScriptKind,
    uploads: list[tuple[str, bytes]],
    *,
    rules_from: str | None = None,
  ) -> list[CheckScript]:
    """Store uploaded script variants in the package dir and register them like an import would.

    An audit script whose name is not a ``check_script`` in profile_rules.json reuses the
    interpreter rules of an existing audit script (``rules_from``); the file still runs.
    """
    from secaudit_core.package_paths import normalize_shell_script_bytes
    from secaudit_core.profile_packages import REMEDIATION_SCRIPT_MARKER, execution_type_for_extension

    profile = await self.get_profile(db, profile_id)
    if not profile:
      raise LookupError("Profile not found")
    if not profile.package_path:
      raise FileNotFoundError("Profile package path not set")
    package_dir = Path(profile.package_path)
    if not package_dir.is_dir():
      raise FileNotFoundError("Profile package directory not found")

    taken = {script.script_file.lower() for script in profile.check_scripts}
    prepared: list[tuple[str, bytes]] = []
    for filename, content in uploads:
      name = Path(filename.replace("\\", "/")).name.strip()
      suffix = Path(name).suffix.lower()
      if not name or suffix not in {".sh", ".py", ".ps1"}:
        raise ValueError(f"Unsupported script file: {filename}")
      if not content or len(content) > MAX_SCRIPT_CONTENT_BYTES:
        raise ValueError(f"Script must be 1..{MAX_SCRIPT_CONTENT_BYTES} bytes: {name}")
      # Discovery decides script kind by the file-name marker, so enforce it here too.
      if kind is ScriptKind.REMEDIATION and REMEDIATION_SCRIPT_MARKER not in name.lower():
        raise ValueError(
          f"Remediation script name must contain '{REMEDIATION_SCRIPT_MARKER}': {name}"
        )
      if kind is ScriptKind.AUDIT and REMEDIATION_SCRIPT_MARKER in name.lower():
        raise ValueError(
          f"Audit script name must not contain '{REMEDIATION_SCRIPT_MARKER}': {name}"
        )
      if (
        name.lower() in taken
        or any(item[0].lower() == name.lower() for item in prepared)
        or (package_dir / name).exists()
      ):
        raise ValueError(f"Script already exists: {name}")
      payload = normalize_shell_script_bytes(content) if suffix == ".sh" else content
      prepared.append((name, payload))

    written: list[Path] = []
    bindings: dict[str, list[dict]] = {}
    try:
      for name, payload in prepared:
        target = self._resolve_script_path(str(package_dir), name)
        target.write_bytes(payload)
        written.append(target)

      package = load_profile_package(package_dir)
      items = {
        item["script_file"]: item
        for item in (*package["scripts"], *package["remediation_scripts"])
      }
      for path in written:
        item = items.get(path.name)
        if item is not None:
          bindings[path.name] = list(item.get("context", []))

      unresolved = [path.name for path in written if path.name not in items]
      if unresolved and kind is ScriptKind.REMEDIATION:
        # Reserved/excluded names would never be discovered, so they must not be stored.
        raise ValueError(
          "Remediation script is not discoverable in the package (reserved name): "
          + ", ".join(unresolved)
        )
      if unresolved:
        base = self._rules_base_script(profile, rules_from)
        base_rules = [
          {
            "regex": rule.regex,
            "extraction_type": rule.extraction_type,
            "tech_name": rule.tech_name,
          }
          for rule in (base.interpreter_rules if base is not None else [])
        ]
        for name in unresolved:
          bindings[name] = base_rules
    except Exception:
      for path in written:
        path.unlink(missing_ok=True)
      raise

    created: list[CheckScript] = []
    for name, _ in prepared:
      item = items.get(name)
      if item is not None:
        script = CheckScript(
          profile_id=profile.id,
          name=item["name"],
          execution_type=map_execution_type(item.get("type", "SSH")),
          script_file=item["script_file"],
          script_kind=kind,
          description=item.get("description"),
        )
      else:
        script = CheckScript(
          profile_id=profile.id,
          name=Path(name).stem,
          execution_type=execution_type_for_extension(Path(name)),
          script_file=name,
          script_kind=kind,
          description=None,
        )
      rules: list[InterpreterRule] = []
      for rule in bindings.get(name, []):
        tech_name = rule.get("tech_name") or rule.get("techName")
        if not tech_name:
          continue
        rules.append(
          InterpreterRule(
            regex=rule["regex"],
            extraction_type=rule.get("extraction_type") or rule.get("extractionType") or "SINGLE",
            tech_name=tech_name,
          )
        )
      script.interpreter_rules = rules
      db.add(script)
      created.append(script)
    # A profile without an active script of this kind would run nothing, so the first upload takes over.
    has_active = any(
      item.script_kind == kind and item.is_primary for item in profile.check_scripts
    )
    if created and not has_active:
      created[0].is_primary = True
    await db.flush()
    return created

  def _rules_base_script(self, profile: Profile, rules_from: str | None) -> CheckScript | None:
    """Pick the audit script whose interpreter rules parse a script with a new name."""
    audit = [script for script in profile.check_scripts if script.script_kind == ScriptKind.AUDIT]
    if rules_from:
      wanted = rules_from.strip()
      for script in audit:
        if wanted in {script.name, script.script_file, Path(script.script_file).stem}:
          return script
      raise ValueError(f"Rules base script not found: {rules_from}")
    if len(audit) == 1:
      return audit[0]
    if not audit:
      return None
    raise ValueError("Choose the audit script whose checks this script provides (rules_from)")

  async def delete_check_script(
    self,
    db: AsyncSession,
    profile_id: int,
    script_id: int,
  ) -> None:
    profile, script = await self._get_script_record(db, profile_id, script_id)

    # A job pinned to this variant would silently fall back to all scripts after removal.
    in_use = await db.scalar(
      select(func.count())
      .select_from(RemediationJob)
      .where(RemediationJob.remediation_script_id == script.id)
    )
    if in_use:
      raise ValueError(f"Script is used by {in_use} remediation job(s)")

    await db.execute(delete(InterpreterRule).where(InterpreterRule.check_script_id == script.id))
    await db.execute(delete(CheckScript).where(CheckScript.id == script.id))
    await db.flush()

    # A profile always keeps one active script per kind; promote the next one after a delete.
    if script.is_primary:
      replacement = next(
        (
          item
          for item in profile.check_scripts
          if item.id != script.id and item.script_kind == script.script_kind
        ),
        None,
      )
      if replacement is not None:
        replacement.is_primary = True
        await db.flush()

    if profile.package_path:
      try:
        self._resolve_script_path(profile.package_path, script.script_file).unlink(missing_ok=True)
      except (OSError, ValueError):
        pass

  async def set_primary_check_script(
    self,
    db: AsyncSession,
    profile_id: int,
    script_id: int,
  ) -> CheckScript:
    """Make this script the only active one of its kind (audit or remediation)."""
    profile, script = await self._get_script_record(db, profile_id, script_id)

    for other in profile.check_scripts:
      if (
        other.id != script.id
        and other.script_kind == script.script_kind
        and other.is_primary
      ):
        other.is_primary = False
    # Free the unique slot before activating the new script in the same transaction.
    await db.flush()
    script.is_primary = True
    await db.flush()
    return script

  async def get_profile_rules(self, db: AsyncSession, profile_id: int) -> list[dict]:
    profile = await self.get_profile(db, profile_id)
    if not profile:
      raise LookupError("Profile not found")

    if profile.package_path:
      package_dir = Path(profile.package_path)
      if package_dir.is_dir():
        rules = load_profile_rules_metadata(package_dir)
        if rules:
          return rules

    rules: list[dict] = []
    for script in profile.check_scripts:
      for rule in script.interpreter_rules:
        rules.append(
          {
            "num": str(len(rules) + 1),
            "tech_name": rule.tech_name,
            "requirement_id": rule.tech_name,
            "title": None,
            "explanation": None,
            "impact": None,
            "scope": None,
            "check_script": script.name,
          }
        )
    return rules

  async def get_profile_rule_changelog(
    self,
    db: AsyncSession,
    profile_id: int,
    *,
    limit: int | None = 100,
  ) -> list[dict]:
    profile = await self.get_profile(db, profile_id)
    if not profile:
      raise LookupError("Profile not found")
    if not profile.package_path:
      return []
    package_dir = Path(profile.package_path)
    if not package_dir.is_dir():
      return []
    return load_rule_changelog(package_dir, limit=limit)

  async def update_profile_rule(
    self,
    db: AsyncSession,
    profile_id: int,
    requirement_id: str,
    updates: dict,
    *,
    actor: str | None = None,
  ) -> dict:
    profile = await self.get_profile(db, profile_id)
    if not profile:
      raise LookupError("Profile not found")
    if not profile.package_path:
      raise FileNotFoundError("Profile package path not set")

    package_dir = Path(profile.package_path)
    if not package_dir.is_dir():
      raise FileNotFoundError("Profile package directory not found")

    result = update_profile_rule_in_package(
      package_dir,
      requirement_id,
      updates,
      actor=actor,
    )

    profile.version = result["profile_version"]
    rule_meta = result["rule"]
    title = rule_meta.get("title")
    if isinstance(title, str):
      title = title.strip()[:512] or None

    from secaudit_core.rule_tech_names import RULE_TECH_NAME_MAX

    # Match persisted Rule rows (full id, legacy 64-char truncation, or collision suffix).
    rid = str(rule_meta.get("requirement_id") or requirement_id).strip()
    candidates = [rid[:RULE_TECH_NAME_MAX]]
    if len(rid) > 64:
      candidates.append(rid[:64])
    db_result = await db.execute(
      select(Rule).where(Rule.profile_id == profile.id, Rule.tech_name.in_(candidates))
    )
    db_rule = db_result.scalar_one_or_none()
    if db_rule is not None:
      db_rule.title = title
      db_rule.description = rule_meta.get("explanation")
      if rule_meta.get("criticality") or rule_meta.get("impact"):
        db_rule.severity = rule_meta.get("criticality") or rule_meta.get("impact")

    await db.flush()
    return result

  async def active_profile_version(
    self, db: AsyncSession, profile_id: int
  ) -> ProfileVersion | None:
    result = await db.execute(
      select(ProfileVersion).where(
        ProfileVersion.profile_id == profile_id,
        ProfileVersion.is_active.is_(True),
      )
    )
    return result.scalars().first()

  def _profile_version_payload(self, version: ProfileVersion) -> dict:
    return {
      "id": version.id,
      "profile_id": version.profile_id,
      "number": version.number,
      "label": version.label,
      "enabled_count": len(version.requirement_ids or []),
      "is_active": version.is_active,
      "created_by": version.created_by,
      "created_at": version.created_at,
    }

  async def list_profile_versions(self, db: AsyncSession, profile_id: int) -> list[dict]:
    exists = await db.execute(select(Profile.id).where(Profile.id == profile_id))
    if exists.scalar_one_or_none() is None:
      raise LookupError("Profile not found")
    result = await db.execute(
      select(ProfileVersion)
      .where(ProfileVersion.profile_id == profile_id)
      .order_by(ProfileVersion.number)
    )
    return [self._profile_version_payload(version) for version in result.scalars().all()]

  async def get_profile_version(
    self, db: AsyncSession, profile_id: int, version_id: int
  ) -> ProfileVersion:
    version = await db.get(ProfileVersion, version_id)
    if not version or version.profile_id != profile_id:
      raise LookupError("Profile version not found")
    return version

  async def create_profile_version(
    self,
    db: AsyncSession,
    profile_id: int,
    *,
    requirement_ids: list[str] | None,
    label: str | None,
    activate: bool,
    actor: str | None = None,
  ) -> dict:
    profile = await self.get_profile(db, profile_id)
    if not profile:
      raise LookupError("Profile not found")

    rules = await self.get_profile_rules(db, profile_id)
    known = {str(rule["requirement_id"]) for rule in rules if rule.get("requirement_id")}
    if requirement_ids is None:
      active = await self.active_profile_version(db, profile_id)
      selected = list(active.requirement_ids or []) if active else []
      if not selected:
        selected = [
          str(rule["requirement_id"]) for rule in rules if rule.get("requirement_id")
        ]
    else:
      selected = [str(rid).strip() for rid in requirement_ids]
      selected = [rid for rid in dict.fromkeys(selected) if rid]
    # A package resync can retire requirements that an older version still lists.
    if known:
      selected = [rid for rid in selected if rid in known]
    if not selected:
      raise ValueError("Select at least one check")

    if activate:
      existing = await db.execute(
        select(ProfileVersion).where(ProfileVersion.profile_id == profile_id)
      )
      for item in existing.scalars().all():
        item.is_active = False
      await db.flush()
    last_number = (
      await db.execute(
        select(func.max(ProfileVersion.number)).where(ProfileVersion.profile_id == profile_id)
      )
    ).scalar() or 0
    version = ProfileVersion(
      profile_id=profile_id,
      number=last_number + 1,
      label=label,
      requirement_ids=selected,
      is_active=activate,
      created_by=actor,
    )
    db.add(version)
    await db.flush()
    return self._profile_version_payload(version) | {"requirement_ids": version.requirement_ids}

  async def activate_profile_version(
    self, db: AsyncSession, profile_id: int, version_id: int
  ) -> dict:
    target = await self.get_profile_version(db, profile_id, version_id)
    existing = await db.execute(
      select(ProfileVersion).where(ProfileVersion.profile_id == profile_id)
    )
    # Deactivate first: the partial unique index allows one active row per profile.
    for item in existing.scalars().all():
      if item.id != target.id and item.is_active:
        item.is_active = False
    await db.flush()
    target.is_active = True
    await db.flush()
    return self._profile_version_payload(target)

  async def get_profile_version_dependencies(
    self, db: AsyncSession, profile_id: int, version_id: int
  ) -> dict:
    version = await self.get_profile_version(db, profile_id, version_id)
    jobs = await self._load_jobs(db, Job.profile_version_id == version.id)
    runs = [run for job in jobs for run in job.runs]
    return {
      "jobs": len(jobs),
      "job_runs": len(runs),
      "check_results": sum(len(run.check_results) for run in runs),
      "active_runs": sum(
        1 for run in runs if run.status in (JobStatus.PENDING, JobStatus.RUNNING)
      ),
    }

  async def delete_profile_version(
    self,
    db: AsyncSession,
    profile_id: int,
    version_id: int,
    *,
    cascade: bool = False,
  ) -> dict:
    version = await self.get_profile_version(db, profile_id, version_id)
    if version.is_active:
      raise ProfileVersionInUseError("Active version cannot be deleted")

    jobs = await self._load_jobs(db, Job.profile_version_id == version.id)
    runs = [run for job in jobs for run in job.runs]
    if any(run.status in (JobStatus.PENDING, JobStatus.RUNNING) for run in runs):
      raise ProfileVersionInUseError("Stop active runs before deleting this version")
    if jobs and not cascade:
      raise ProfileVersionInUseError(
        f"Version is used by {len(jobs)} job(s); delete with cascade"
      )

    counts = await self._cascade_delete_jobs(db, jobs)
    payload = self._profile_version_payload(version)
    await db.delete(version)
    await db.flush()
    return payload | counts

  async def get_profile(self, db: AsyncSession, profile_id: int) -> Profile | None:
    result = await db.execute(
      select(Profile)
      .options(
        selectinload(Profile.category),
        selectinload(Profile.check_scripts).selectinload(CheckScript.interpreter_rules),
      )
      .where(Profile.id == profile_id)
    )
    return result.scalar_one_or_none()

  async def create_profile(self, db: AsyncSession, data: ProfileCreate) -> Profile:
    profile = Profile(**data.model_dump())
    db.add(profile)
    await db.flush()
    result = await db.execute(
      select(Profile).options(selectinload(Profile.category)).where(Profile.id == profile.id)
    )
    return result.scalar_one()

  async def _resolve_category(
    self,
    db: AsyncSession,
    category_id: int | None,
    category_slug: str | None,
  ) -> Category:
    if category_id:
      category = await db.get(Category, category_id)
      if not category:
        raise ValueError("Category not found")
      return category

    if not category_slug:
      raise ValueError("Could not determine profile category")

    result = await db.execute(select(Category).where(Category.slug == category_slug))
    category = result.scalar_one_or_none()
    if not category:
      raise ValueError(f"Category not found for slug '{category_slug}'")
    return category

  def _persist_rule_rows(self, db: AsyncSession, profile: Profile, package_dir: Path) -> None:
    from secaudit_core.rule_tech_names import allocate_rule_tech_name

    seen: set[str] = set()
    for meta in load_profile_rules_metadata(package_dir):
      base = str(meta.get("requirement_id") or meta.get("tech_name") or "").strip()
      if not base:
        continue
      tech_name = allocate_rule_tech_name(base, seen)
      title = meta.get("title") or None
      if isinstance(title, str):
        title = title.strip()[:512] or None
      db.add(
        Rule(
          profile_id=profile.id,
          tech_name=tech_name,
          title=title,
          description=meta.get("explanation"),
          severity=meta.get("criticality") or meta.get("impact"),
          scap_rule_id=meta.get("scap_rule_id"),
        )
      )

  async def _import_package_dir(
    self,
    db: AsyncSession,
    package_dir: Path,
    *,
    category_id: int | None = None,
    source_format: str = "custom",
    replace_existing: bool = False,
  ) -> Profile:
    package = load_profile_package(package_dir)
    meta = package["profile"]
    scripts = package["scripts"]
    remediation_scripts = package.get("remediation_scripts", [])
    category_slug = meta.get("category_slug") or package.get("category_slug")
    category = await self._resolve_category(db, category_id, category_slug)
    resolved_format = meta.get("source_format") or source_format or "custom"
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

    existing_result = await db.execute(
      select(Profile)
      .options(selectinload(Profile.check_scripts))
      .where(Profile.profile_name == name)
    )
    profile = existing_result.scalar_one_or_none()
    if profile and not replace_existing:
      raise ValueError(f"Profile '{name}' already imported")

    stored_path = self._persist_package(package_dir, name)
    from secaudit_core.profile_packages import ensure_compliance_playbook_declared

    # Catalog mount (/profiles) is read-only; declare/normalize only on writable storage copy.
    ensure_compliance_playbook_declared(stored_path)
    job_script_files: dict[int, str] = {}
    primary_by_kind: dict[ScriptKind, tuple[str, str]] = {}
    if profile is None:
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
      await db.flush()
    else:
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
      job_script_files = await db.run_sync(
        lambda sync_session: capture_remediation_script_links(sync_session, profile.id)
      )
      # Selection survives a resync when the selected file is still in the package.
      primary_by_kind = {
        item.script_kind: (item.execution_type.value, item.script_file)
        for item in profile.check_scripts
        if item.is_primary
      }
      await db.run_sync(lambda sync_session: detach_remediation_script_links(sync_session, profile.id))
      for script in list(profile.check_scripts):
        await db.execute(delete(InterpreterRule).where(InterpreterRule.check_script_id == script.id))
      await db.execute(delete(CheckScript).where(CheckScript.profile_id == profile.id))
      await db.execute(delete(Rule).where(Rule.profile_id == profile.id))
      await db.flush()
    self._persist_rule_rows(db, profile, package_dir)

    # Keep the operator's choice when its file is still packaged; otherwise the packaged
    # script is active by default, so one script of each kind always runs.
    def chosen_primary(items: list[dict], kind: ScriptKind) -> tuple[str, str] | None:
      previous = primary_by_kind.get(kind)
      for item in items:
        key = (map_execution_type(item.get("type", "SSH")).value, item["script_file"])
        if key == previous:
          return key
      if items:
        first = items[0]
        return (
          map_execution_type(first.get("type", "SSH")).value,
          first["script_file"],
        )
      return None

    chosen_audit = chosen_primary(scripts, ScriptKind.AUDIT)
    chosen_remediation = chosen_primary(remediation_scripts, ScriptKind.REMEDIATION)

    for item in scripts:
      execution_type = map_execution_type(item.get("type", "SSH"))
      script = CheckScript(
        profile_id=profile.id,
        name=item["name"],
        execution_type=execution_type,
        script_file=item["script_file"],
        script_kind=ScriptKind.AUDIT,
        description=item.get("description"),
        is_primary=(execution_type.value, item["script_file"]) == chosen_audit,
      )
      db.add(script)
      await db.flush()

      from secaudit_core.rule_tech_names import RULE_TECH_NAME_MAX

      for rule in item.get("context", []):
        tech_name = rule.get("techName") or rule.get("tech_name")
        if not tech_name:
          continue
        db.add(
          InterpreterRule(
            check_script_id=script.id,
            regex=rule["regex"],
            extraction_type=rule.get("extractionType", "SINGLE"),
            tech_name=str(tech_name).strip()[:RULE_TECH_NAME_MAX],
          )
        )

    for item in remediation_scripts:
      script_path = package_dir / item["script_file"]
      if not script_path.is_file():
        raise FileNotFoundError(f"Remediation script not found: {item['script_file']}")
      script = CheckScript(
        profile_id=profile.id,
        name=item["name"],
        execution_type=map_execution_type(item.get("type", "SSH")),
        script_file=item["script_file"],
        script_kind=ScriptKind.REMEDIATION,
        description=item.get("description"),
        is_primary=(
          map_execution_type(item.get("type", "SSH")).value,
          item["script_file"],
        )
        == chosen_remediation,
      )
      db.add(script)

    await db.flush()
    if job_script_files:
      await db.run_sync(
        lambda sync_session: restore_remediation_script_links(
          sync_session, profile.id, job_script_files
        )
      )
      await db.flush()

    from secaudit_core.compliance_playbooks import upsert_compliance_playbook_for_profile

    await db.run_sync(
      lambda sync_session: upsert_compliance_playbook_for_profile(
        sync_session, profile, package_dir=Path(stored_path)
      )
    )
    await db.flush()

    result = await db.execute(
      select(Profile).options(selectinload(Profile.category)).where(Profile.id == profile.id)
    )
    return result.scalar_one()

  async def import_from_path(
    self,
    db: AsyncSession,
    package_path: str,
    category_id: int | None = None,
    *,
    replace_existing: bool = False,
  ) -> Profile:
    path = self._assert_import_path_allowed(package_path)
    if not path.exists():
      raise FileNotFoundError(f"Profile package not found at {package_path}")
    return await self._import_package_dir(
      db,
      path,
      category_id=category_id,
      replace_existing=replace_existing,
    )

  async def import_from_upload(
    self,
    db: AsyncSession,
    uploads: list[tuple[str, bytes]],
    category_id: int | None = None,
    *,
    scap_profile_id: str | None = None,
    replace_existing: bool = False,
    compliance_playbook: tuple[str, bytes] | None = None,
  ) -> Profile:
    package_dir, temp_dir = materialize_uploaded_package(uploads)
    try:
      package_dir, source_format = prepare_upload_package(
        package_dir,
        scap_profile_id=scap_profile_id,
      )
      from secaudit_core.profile_packages import ensure_compliance_playbook_declared

      if compliance_playbook is not None:
        filename, content = compliance_playbook
        ensure_compliance_playbook_declared(
          package_dir,
          filename=filename,
          content=content,
        )
      else:
        ensure_compliance_playbook_declared(package_dir)
      return await self._import_package_dir(
        db,
        package_dir,
        category_id=category_id,
        source_format=source_format,
        replace_existing=replace_existing,
      )
    finally:
      temp_dir.cleanup()

  async def list_catalog(
    self,
    db: AsyncSession,
    *,
    family: str | None = None,
    platform: str | None = None,
    os_name: str | None = None,
    os_version: str | None = None,
    os: str | None = None,
  ) -> list[dict]:
    entries = await build_catalog(db, family=family)
    if platform:
      entries = [entry for entry in entries if entry.get("platform") == platform]
    if os_name:
      needle = os_name.strip().lower()
      entries = [
        entry
        for entry in entries
        if needle in str(entry.get("os_name") or "").lower()
      ]
    if os_version:
      needle = os_version.strip().lower()
      entries = [
        entry
        for entry in entries
        if needle in str(entry.get("os_version") or "").lower()
      ]
    if os:
      os_filter = os.strip().lower()
      entries = [
        entry
        for entry in entries
        if os_slug(entry.get("os_name")) == os_filter
        or str(entry.get("os_name") or "").lower() == os_filter
      ]
    return entries

  def _resolve_sync_package_path(self, profile: Profile, catalog: list[dict]) -> str | None:
    latest = next(
      (
        entry
        for entry in catalog
        if entry.get("profile_name") == profile.profile_name and entry.get("is_latest")
      ),
      None,
    )
    if latest:
      return latest["package_path"]
    # Prefer the read-only mount source over stored copy so re-sync picks up
    # renamed scripts / layout changes even when catalog lookup missed.
    mount_root = Path(settings.profiles_path)
    if mount_root.is_dir():
      for package_dir in discover_importable_package_dirs(mount_root):
        profile_file = package_dir / "description.json"
        if not profile_file.is_file():
          continue
        try:
          meta = json.loads(profile_file.read_text(encoding="utf-8-sig"))
          if profile_name_from_meta(meta) == profile.profile_name:
            return str(package_dir)
        except (OSError, json.JSONDecodeError):
          continue
    if profile.package_path:
      path = Path(profile.package_path)
      if path.is_dir():
        return str(path)
    return None

  async def sync_profile(self, db: AsyncSession, profile_id: int) -> Profile:
    profile = await self.get_profile(db, profile_id)
    if not profile:
      raise LookupError("Profile not found")

    catalog = await build_catalog(db)
    package_path = self._resolve_sync_package_path(profile, catalog)
    if not package_path:
      raise ValueError("No catalog source found for profile re-sync")

    return await self.import_from_path(db, package_path, replace_existing=True)

  async def bulk_set_active(
    self,
    db: AsyncSession,
    profile_ids: list[int],
    *,
    is_active: bool,
  ) -> dict:
    succeeded: list[int] = []
    failed: list[dict[str, str | int]] = []
    seen: set[int] = set()

    for profile_id in profile_ids:
      if profile_id in seen:
        continue
      seen.add(profile_id)
      profile = await db.get(Profile, profile_id)
      if not profile:
        failed.append({"profile_id": profile_id, "message": "Profile not found"})
        continue
      profile.is_active = is_active
      succeeded.append(profile_id)

    await db.flush()
    return {"succeeded": succeeded, "failed": failed}

  async def bulk_delete(
    self,
    db: AsyncSession,
    profile_ids: list[int],
    *,
    cascade: bool = False,
    options: ProfileDeleteOptions | None = None,
  ) -> dict:
    succeeded: list[int] = []
    failed: list[dict] = []
    seen: set[int] = set()

    for profile_id in profile_ids:
      if profile_id in seen:
        continue
      seen.add(profile_id)
      try:
        await self.delete_profile(db, profile_id, cascade=cascade, options=options)
        succeeded.append(profile_id)
      except LookupError:
        failed.append({"profile_id": profile_id, "message": "Profile not found"})
      except ProfileDependencyError as exc:
        failed.append(
          {
            "profile_id": profile_id,
            "message": str(exc),
            "code": exc.code,
            "dependencies": exc.dependencies.model_dump(),
          }
        )
      except ProfileActiveRunsError as exc:
        failed.append(
          {
            "profile_id": profile_id,
            "message": str(exc),
            "code": exc.code,
            "dependencies": exc.dependencies.model_dump(),
          }
        )
      except ValueError as exc:
        failed.append({"profile_id": profile_id, "message": str(exc)})

    return {"succeeded": succeeded, "failed": failed}

  async def bulk_sync(self, db: AsyncSession, profile_ids: list[int]) -> dict:
    succeeded: list[int] = []
    failed: list[dict[str, str | int]] = []
    seen: set[int] = set()

    for profile_id in profile_ids:
      if profile_id in seen:
        continue
      seen.add(profile_id)
      try:
        await self.sync_profile(db, profile_id)
        succeeded.append(profile_id)
      except LookupError:
        failed.append({"profile_id": profile_id, "message": "Profile not found"})
      except (ValueError, FileNotFoundError, OSError) as exc:
        failed.append({"profile_id": profile_id, "message": str(exc)})

    return {"succeeded": succeeded, "failed": failed}

  async def import_bulk(
    self,
    db: AsyncSession,
    package_paths: list[str],
    *,
    skip_existing: bool = True,
    update_existing: bool = False,
  ) -> dict:
    imported: list[Profile] = []
    skipped: list[str] = []
    errors: list[dict[str, str]] = []

    for package_path in package_paths:
      try:
        # Isolate each package so one IntegrityError cannot abort the whole bulk txn.
        async with db.begin_nested():
          profile = await self.import_from_path(
            db,
            package_path,
            replace_existing=update_existing,
          )
          imported.append(profile)
      except ValueError as exc:
        message = str(exc)
        if skip_existing and "already imported" in message.lower():
          skipped.append(package_path)
        else:
          errors.append({"package_path": package_path, "message": message})
      except FileNotFoundError as exc:
        errors.append({"package_path": package_path, "message": str(exc)})
      except Exception as exc:
        errors.append({"package_path": package_path, "message": str(exc)})

    return {"imported": imported, "skipped": skipped, "errors": errors}

  async def preview_catalog_rules(self, package_path: str, *, limit: int = 200) -> list[dict]:
    package_dir = self._assert_import_path_allowed(package_path)
    if not package_dir.exists() or not package_dir.is_dir():
      raise FileNotFoundError(f"Profile package not found at {package_path}")
    return load_profile_rules_metadata(package_dir, limit=limit)

  async def get_catalog_sync_status(self, db: AsyncSession) -> dict:
    """Return scheduled-sync config and last run from Redis (no filesystem scan)."""
    last_run = load_catalog_sync_status(settings.redis_url)
    mount = Path(settings.profiles_path)

    status = {
      "enabled": settings.profiles_catalog_sync_enabled,
      "interval_seconds": settings.profiles_catalog_sync_interval_seconds,
      "update_existing": settings.profiles_catalog_sync_update_existing,
      "mount_path": settings.profiles_path,
      "mount_available": mount.exists(),
      "pending_imports": 0,
      "pending_updates": 0,
      "last_run_at": None,
      "last_run_skipped": False,
      "last_run_skip_reason": None,
      "last_imported_count": 0,
      "last_updated_count": 0,
      "last_skipped_count": 0,
      "last_error_count": 0,
    }

    if last_run:
      status["last_run_at"] = last_run.get("finished_at")
      skipped_flag = last_run.get("skipped")
      if skipped_flag is True:
        status["last_run_skipped"] = True
        status["last_run_skip_reason"] = last_run.get("reason")
      else:
        status["last_run_skipped"] = False
        status["last_run_skip_reason"] = None
        status["last_imported_count"] = len(last_run.get("imported") or [])
        status["last_updated_count"] = len(last_run.get("updated") or [])
        status["last_skipped_count"] = len(skipped_flag or []) if isinstance(skipped_flag, list) else 0
        status["last_error_count"] = len(last_run.get("errors") or [])

    return status

  async def seed_bundled_profiles(self, db: AsyncSession) -> int:
    """Import all bundled catalog entries not yet registered (when auto-seed is enabled)."""
    if not settings.profiles_auto_seed:
      return 0

    catalog = await build_catalog(db)
    imported_count = 0
    for entry in catalog:
      if entry["imported"]:
        continue
      try:
        await self.import_from_path(db, entry["package_path"])
        imported_count += 1
      except (ValueError, FileNotFoundError):
        continue
    return imported_count

  async def migrate_legacy_packages(self, db: AsyncSession) -> None:
    """Copy profiles still pointing at the read-only mount into persistent storage."""
    storage_root = self._storage_root().resolve()
    result = await db.execute(select(Profile))
    for profile in result.scalars().all():
      if not profile.package_path:
        continue
      pkg = Path(profile.package_path)
      try:
        resolved = pkg.resolve()
      except OSError:
        continue
      if resolved == storage_root or storage_root in resolved.parents:
        continue
      if not pkg.is_dir():
        continue
      stored_path = self._persist_package(pkg, profile.profile_name)
      profile.package_path = str(stored_path)
    await db.flush()

  async def reconcile_profile_categories(self, db: AsyncSession) -> int:
    """Re-apply category inference and normalize legacy profile_family tags to custom."""
    updated = 0
    result = await db.execute(select(Profile))
    for profile in result.scalars().all():
      if profile.profile_family != "custom":
        profile.profile_family = "custom"
        updated += 1
      if not profile.package_path:
        continue
      package_dir = Path(profile.package_path)
      if not package_dir.is_dir():
        continue

      slug = infer_category_from_package_dir(package_dir)
      category_result = await db.execute(select(Category).where(Category.slug == slug))
      category = category_result.scalar_one_or_none()
      if category and profile.category_id != category.id:
        profile.category_id = category.id
        updated += 1

    await db.flush()
    return updated

  async def scan_profiles_directory(self, db: AsyncSession) -> list[str]:
    """Scan mounted profiles path and return discovered package directories."""
    root = Path(settings.profiles_path)
    return [str(package_dir) for package_dir in discover_importable_package_dirs(root)]

  async def get_profile_dependencies(self, db: AsyncSession, profile_id: int) -> ProfileDependencies:
    profile = await self.get_profile(db, profile_id)
    if not profile:
      raise LookupError("Profile not found")

    playbook_ids = list(
      (await db.execute(select(Playbook.id).where(Playbook.profile_id == profile_id))).scalars().all()
    )
    job_ids = list(
      (await db.execute(select(Job.id).where(Job.profile_id == profile_id))).scalars().all()
    )
    if playbook_ids:
      playbook_job_ids = list(
        (
          await db.execute(select(Job.id).where(Job.playbook_id.in_(playbook_ids)))
        )
        .scalars()
        .all()
      )
      job_ids = list({*job_ids, *playbook_job_ids})

    jobs_count = len(job_ids)
    remediation_count = (
      await db.execute(
        select(func.count()).select_from(RemediationJob).where(RemediationJob.profile_id == profile_id)
      )
    ).scalar_one()
    waivers_count = (
      await db.execute(
        select(func.count()).select_from(ComplianceWaiver).where(ComplianceWaiver.profile_id == profile_id)
      )
    ).scalar_one()

    remediation_ids = list(
      (
        await db.execute(select(RemediationJob.id).where(RemediationJob.profile_id == profile_id))
      )
      .scalars()
      .all()
    )

    job_runs = 0
    check_results = 0
    active_job_runs = 0
    if job_ids:
      job_runs = (
        await db.execute(select(func.count()).select_from(JobRun).where(JobRun.job_id.in_(job_ids)))
      ).scalar_one()
      check_results = (
        await db.execute(
          select(func.count())
          .select_from(CheckResult)
          .join(JobRun, JobRun.id == CheckResult.job_run_id)
          .where(JobRun.job_id.in_(job_ids))
        )
      ).scalar_one()
      active_job_runs = (
        await db.execute(
          select(func.count())
          .select_from(JobRun)
          .where(
            JobRun.job_id.in_(job_ids),
            JobRun.status.in_((JobStatus.PENDING, JobStatus.RUNNING)),
          )
        )
      ).scalar_one()

    remediation_runs = 0
    active_remediation_runs = 0
    if remediation_ids:
      remediation_runs = (
        await db.execute(
          select(func.count())
          .select_from(RemediationRun)
          .where(RemediationRun.remediation_job_id.in_(remediation_ids))
        )
      ).scalar_one()
      active_remediation_runs = (
        await db.execute(
          select(func.count())
          .select_from(RemediationRun)
          .where(
            RemediationRun.remediation_job_id.in_(remediation_ids),
            RemediationRun.status.in_((JobStatus.PENDING, JobStatus.RUNNING)),
          )
        )
      ).scalar_one()

    playbooks_count = len(playbook_ids)

    return ProfileDependencies(
      jobs=jobs_count,
      remediation_jobs=remediation_count,
      waivers=waivers_count,
      playbooks=playbooks_count,
      job_runs=job_runs,
      check_results=check_results,
      remediation_runs=remediation_runs,
      active_runs=active_job_runs + active_remediation_runs,
    )

  async def _cancel_dispatchable_outbox(
    self,
    db: AsyncSession,
    *,
    callback_kind: str,
    run_ids: list[int],
  ) -> None:
    """Terminally cancel PENDING/DISPATCHING outbox rows for runs about to be deleted."""
    if not run_ids:
      return
    await db.execute(
      update(TaskOutbox)
      .where(
        TaskOutbox.callback_kind == callback_kind,
        TaskOutbox.callback_ref_id.in_(run_ids),
        TaskOutbox.status.in_((OutboxStatus.PENDING, OutboxStatus.DISPATCHING)),
      )
      .values(
        status=OutboxStatus.CANCELLED,
        last_error="Cancelled because related run was removed by profile cascade delete",
        dispatch_started_at=None,
      )
    )

  async def _load_jobs(self, db: AsyncSession, condition) -> list[Job]:
    result = await db.execute(
      select(Job)
      .options(
        selectinload(Job.runs).selectinload(JobRun.check_results),
        selectinload(Job.job_hosts),
      )
      .where(condition)
    )
    return list(result.scalars().all())

  async def _cascade_delete_jobs(self, db: AsyncSession, jobs: list[Job]) -> dict:
    if not jobs:
      return {"deleted_jobs": 0, "deleted_job_runs": 0, "deleted_check_results": 0}

    job_ids = [job.id for job in jobs]
    run_ids = [run.id for job in jobs for run in job.runs]
    check_results = sum(len(run.check_results) for job in jobs for run in job.runs)

    await self._cancel_dispatchable_outbox(db, callback_kind="job_run", run_ids=run_ids)

    if run_ids:
      await db.execute(
        delete(ScheduledReportDeliveryAttempt).where(
          ScheduledReportDeliveryAttempt.job_run_id.in_(run_ids)
        )
      )
      await db.execute(
        update(ScheduledReport)
        .where(ScheduledReport.last_delivered_run_id.in_(run_ids))
        .values(last_delivered_run_id=None)
      )
      await db.execute(update(Job).where(Job.id.in_(job_ids)).values(baseline_run_id=None))

    await db.execute(delete(ScheduledReport).where(ScheduledReport.job_id.in_(job_ids)))
    await db.execute(
      update(ComplianceWaiver).where(ComplianceWaiver.job_id.in_(job_ids)).values(job_id=None)
    )

    for job in jobs:
      for job_run in list(job.runs):
        for check in list(job_run.check_results):
          await db.delete(check)
        await db.delete(job_run)
      for job_host in list(job.job_hosts):
        await db.delete(job_host)
      await db.delete(job)

    await db.flush()
    return {
      "deleted_jobs": len(jobs),
      "deleted_job_runs": len(run_ids),
      "deleted_check_results": check_results,
    }

  async def _cascade_delete_jobs_for_profile(self, db: AsyncSession, profile_id: int) -> None:
    jobs = await self._load_jobs(db, Job.profile_id == profile_id)
    await self._cascade_delete_jobs(db, jobs)

  async def _cascade_delete_remediation_jobs_for_profile(self, db: AsyncSession, profile_id: int) -> None:
    result = await db.execute(
      select(RemediationJob)
      .options(
        selectinload(RemediationJob.runs).selectinload(RemediationRun.results),
        selectinload(RemediationJob.job_hosts),
      )
      .where(RemediationJob.profile_id == profile_id)
    )
    jobs = list(result.scalars().all())
    run_ids = [run.id for job in jobs for run in job.runs]
    await self._cancel_dispatchable_outbox(
      db, callback_kind="remediation_run", run_ids=run_ids
    )
    for job in jobs:
      job.remediation_script_id = None
      for remediation_run in list(job.runs):
        for item in list(remediation_run.results):
          await db.delete(item)
        await db.delete(remediation_run)
      for job_host in list(job.job_hosts):
        await db.delete(job_host)
      await db.delete(job)
    await db.flush()

  async def _cascade_delete_playbooks_for_profile(self, db: AsyncSession, profile_id: int) -> None:
    """Remove compliance/user playbooks bound to the profile and their playbook jobs."""
    playbook_ids = list(
      (await db.execute(select(Playbook.id).where(Playbook.profile_id == profile_id))).scalars().all()
    )
    if not playbook_ids:
      return

    jobs = await self._load_jobs(db, Job.playbook_id.in_(playbook_ids))
    await self._cascade_delete_jobs(db, jobs)
    await db.execute(
      update(JobTemplate).where(JobTemplate.playbook_id.in_(playbook_ids)).values(playbook_id=None)
    )
    await db.execute(delete(Playbook).where(Playbook.id.in_(playbook_ids)))
    await db.flush()

  async def _detach_jobs_for_profile(self, db: AsyncSession, profile_id: int) -> None:
    await db.execute(update(Job).where(Job.profile_id == profile_id).values(profile_id=None))
    await db.execute(
      update(JobTemplate).where(JobTemplate.profile_id == profile_id).values(profile_id=None)
    )
    await db.flush()

  async def _purge_reports_for_profile(self, db: AsyncSession, profile_id: int) -> None:
    """Delete run history for profile jobs without removing the jobs themselves."""
    jobs = await self._load_jobs(db, Job.profile_id == profile_id)
    if not jobs:
      return
    job_ids = [job.id for job in jobs]
    run_ids = [run.id for job in jobs for run in job.runs]
    await self._cancel_dispatchable_outbox(db, callback_kind="job_run", run_ids=run_ids)
    if run_ids:
      await db.execute(
        delete(ScheduledReportDeliveryAttempt).where(
          ScheduledReportDeliveryAttempt.job_run_id.in_(run_ids)
        )
      )
      await db.execute(
        update(ScheduledReport)
        .where(ScheduledReport.last_delivered_run_id.in_(run_ids))
        .values(last_delivered_run_id=None)
      )
      await db.execute(update(Job).where(Job.id.in_(job_ids)).values(baseline_run_id=None))
    await db.execute(delete(ScheduledReport).where(ScheduledReport.job_id.in_(job_ids)))
    for job in jobs:
      for job_run in list(job.runs):
        for check in list(job_run.check_results):
          await db.delete(check)
        await db.delete(job_run)
    await db.flush()

  async def delete_profile(
    self,
    db: AsyncSession,
    profile_id: int,
    *,
    cascade: bool = False,
    options: ProfileDeleteOptions | None = None,
  ) -> None:
    profile = await self.get_profile(db, profile_id)
    if not profile:
      raise LookupError("Profile not found")

    dependencies = await self.get_profile_dependencies(db, profile_id)
    opts = options or ProfileDeleteOptions()
    if cascade:
      opts = ProfileDeleteOptions(delete_playbooks=True, delete_jobs=True, delete_reports=True)

    # Legacy clients: dependencies still require an explicit cascade / options.
    if dependencies.has_blocking and not cascade and options is None:
      raise ProfileDependencyError(dependencies)

    if dependencies.active_runs > 0:
      raise ProfileActiveRunsError(dependencies)

    if opts.delete_jobs:
      await self._cascade_delete_jobs_for_profile(db, profile_id)
      await self._cascade_delete_remediation_jobs_for_profile(db, profile_id)
      await db.execute(delete(ComplianceWaiver).where(ComplianceWaiver.profile_id == profile_id))
      await db.execute(
        update(JobTemplate).where(JobTemplate.profile_id == profile_id).values(profile_id=None)
      )
    else:
      if opts.delete_reports:
        await self._purge_reports_for_profile(db, profile_id)
      # Remediation jobs and waivers cannot outlive the profile (NOT NULL FKs).
      await self._cascade_delete_remediation_jobs_for_profile(db, profile_id)
      await db.execute(delete(ComplianceWaiver).where(ComplianceWaiver.profile_id == profile_id))
      await self._detach_jobs_for_profile(db, profile_id)

    if opts.delete_playbooks:
      await self._cascade_delete_playbooks_for_profile(db, profile_id)

    package_path = profile.package_path
    for script in profile.check_scripts:
      await db.execute(delete(InterpreterRule).where(InterpreterRule.check_script_id == script.id))
    await db.execute(delete(CheckScript).where(CheckScript.profile_id == profile_id))
    await db.execute(delete(Rule).where(Rule.profile_id == profile_id))
    await db.delete(profile)
    await db.flush()
    self._remove_stored_package(package_path)


ALLOWED_CATEGORY_SLUGS = frozenset(
  {"linux-platform", "windows-platform", "unix-platform", "network-platform", "services"}
)

SLUG_MIGRATIONS = {
  "os-linux": "linux-platform",
  "linux": "linux-platform",
  "os-windows": "windows-platform",
  "windows": "windows-platform",
  "os-unix": "unix-platform",
  "unix": "unix-platform",
  "bsd": "unix-platform",
  "network": "network-platform",
  "network-services": "network-platform",
}

DEFAULT_CATEGORIES = [
  ("Linux Platform", "linux-platform", "os"),
  ("Windows Platform", "windows-platform", "os"),
  ("UNIX Platform", "unix-platform", "os"),
  ("Network Platform", "network-platform", "network"),
  ("Services", "services", "other"),
]


class CategoryService:
  async def list_categories(self, db: AsyncSession) -> list[Category]:
    result = await db.execute(
      select(Category)
      .where(Category.slug.in_(ALLOWED_CATEGORY_SLUGS))
      .order_by(Category.name)
    )
    return list(result.scalars().all())

  async def _upsert_category(
    self,
    db: AsyncSession,
    name: str,
    slug: str,
    cat_type: str,
  ) -> Category:
    by_slug = await db.execute(select(Category).where(Category.slug == slug))
    existing = by_slug.scalar_one_or_none()
    if existing:
      existing.name = name
      existing.category_type = CategoryType(cat_type)
      existing.parent_id = None
      await db.flush()
      return existing

    by_name = await db.execute(select(Category).where(Category.name == name))
    existing = by_name.scalar_one_or_none()
    if existing:
      existing.slug = slug
      existing.category_type = CategoryType(cat_type)
      existing.parent_id = None
      await db.flush()
      return existing

    category = Category(
      name=name,
      slug=slug,
      category_type=CategoryType(cat_type),
      parent_id=None,
    )
    db.add(category)
    await db.flush()
    return category

  async def _merge_category(self, db: AsyncSession, old_slug: str, new_slug: str) -> None:
    old_result = await db.execute(
      select(Category).options(selectinload(Category.profiles)).where(Category.slug == old_slug)
    )
    old = old_result.scalar_one_or_none()
    if not old or old_slug == new_slug:
      return

    target_result = await db.execute(select(Category).where(Category.slug == new_slug))
    target = target_result.scalar_one_or_none()
    if not target:
      old.name = next(n for n, s, _ in DEFAULT_CATEGORIES if s == new_slug)
      old.slug = new_slug
      old.category_type = CategoryType(next(t for _, s, t in DEFAULT_CATEGORIES if s == new_slug))
      old.parent_id = None
      await db.flush()
      return

    for profile in list(old.profiles):
      profile.category_id = target.id
    await db.delete(old)
    await db.flush()

  async def seed_defaults(self, db: AsyncSession) -> None:
    for name, slug, cat_type in DEFAULT_CATEGORIES:
      await self._upsert_category(db, name, slug, cat_type)

    for old_slug, new_slug in SLUG_MIGRATIONS.items():
      await self._merge_category(db, old_slug, new_slug)

    await self.prune_obsolete(db)

  async def prune_obsolete(self, db: AsyncSession) -> None:
    result = await db.execute(
      select(Category).options(selectinload(Category.profiles), selectinload(Category.children))
    )
    categories = list(result.scalars().all())

    for category in categories:
      if category.slug in ALLOWED_CATEGORY_SLUGS:
        category.parent_id = None
        continue

      for profile in list(category.profiles):
        profile.category_id = None

      for child in list(category.children):
        for profile in list(child.profiles):
          profile.category_id = None
        await db.delete(child)

      await db.delete(category)
