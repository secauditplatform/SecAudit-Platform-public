"""Profile package discovery, validation, and loading (shared by API and workers)."""

from __future__ import annotations

import json
import re
from pathlib import Path

from secaudit_core.enums import ExecutionType

SCRIPT_EXTENSIONS: dict[str, ExecutionType] = {
    ".sh": ExecutionType.SSH,
    ".py": ExecutionType.PYTHON,
    ".ps1": ExecutionType.WINRM,
    ".yml": ExecutionType.ANSIBLE,
    ".yaml": ExecutionType.ANSIBLE,
}

EXCLUDED_SCRIPT_MARKERS = ("_dev", "_old", ".sig", "remote_access", "network_checks")
REMEDIATION_SCRIPT_MARKER = "_remediation"

DESCRIPTION_FILE = "description.json"
PROFILE_RULES_JSON = "profile_rules.json"
RULE_CHANGELOG_JSON = "rule_changelog.json"
PLAYBOOK_CHANGELOG_JSON = "playbook_changelog.json"
COMPLIANCE_PLAYBOOK_KEY = "compliance_playbook"
COMPLIANCE_PLAYBOOK_VERSION_KEY = "compliance_playbook_version"
DEFAULT_PLAYBOOK_VERSION = "1.0"
DEFAULT_PROFILE_VERSION = "1.0"
RULES_REF_KEYS = ("profile_rules",)
EDITABLE_RULE_FIELDS = ("title", "explanation", "impact", "scope")
# Canonical profile_rules.json keys → accepted legacy aliases (read-only compatibility).
RULE_FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "title": ("summary", "bench"),
    "explanation": ("description",),
    "impact": ("risk",),
    "scope": ("location",),
    "criticality": ("severity",),
    "check_script": ("script_name",),
    "match_pattern": ("regex", "REGEXP", "regexp"),
}
LEGACY_RULE_FIELD_KEYS = frozenset(
    alias for aliases in RULE_FIELD_ALIASES.values() for alias in aliases
)


def profile_name_from_meta(meta: dict) -> str:
    """Resolve profile_name from description.json (legacy tech_name accepted)."""
    return str(meta.get("profile_name") or meta.get("tech_name") or "").strip()


def normalize_description_meta(meta: dict) -> dict:
    """Return a shallow copy with canonical profile_name / encoding / overview keys."""
    out = dict(meta)
    name = profile_name_from_meta(out)
    if name:
        out["profile_name"] = name
    encoding = out.get("encoding") or out.get("charset")
    if encoding:
        out["encoding"] = str(encoding).strip()
    # Package blurb fields: overview / purpose (legacy summary / detail accepted on read).
    overview = out.get("overview")
    if overview is None:
        overview = out.get("summary")
    if overview is not None:
        out["overview"] = overview
    out.pop("summary", None)
    purpose = out.get("purpose")
    if purpose is None:
        purpose = out.get("detail")
    if purpose is not None:
        out["purpose"] = purpose
    out.pop("detail", None)
    return out


def profile_overview_from_meta(meta: dict) -> str | None:
    """Short profile blurb from description.json (`overview`, legacy `summary`)."""
    value = meta.get("overview")
    if value is None:
        value = meta.get("summary")
    if isinstance(value, str):
        value = value.strip() or None
    return value if value is None or isinstance(value, str) else str(value)


def profile_purpose_from_meta(meta: dict) -> str | None:
    """Longer profile blurb from description.json (`purpose`, legacy `detail`)."""
    value = meta.get("purpose")
    if value is None:
        value = meta.get("detail")
    if isinstance(value, str):
        value = value.strip() or None
    return value if value is None or isinstance(value, str) else str(value)


def map_execution_type(raw_type: str | ExecutionType) -> ExecutionType:
    if isinstance(raw_type, ExecutionType):
        return raw_type
    mapping = {
        "SSH": ExecutionType.SSH,
        "WINRM": ExecutionType.WINRM,
        "POWERSHELL": ExecutionType.WINRM,
        "ANSIBLE": ExecutionType.ANSIBLE,
        "PYTHON": ExecutionType.PYTHON,
    }
    return mapping.get(str(raw_type).upper(), ExecutionType.SSH)


def execution_type_for_extension(path: Path) -> ExecutionType:
    return SCRIPT_EXTENSIONS.get(path.suffix.lower(), ExecutionType.SSH)


def _read_json(path: Path) -> dict:
    with path.open(encoding="utf-8-sig") as handle:
        return json.load(handle)


def _write_json(path: Path, payload: dict | list) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def bump_semver_patch(version: str | None) -> str:
    """Increment the last numeric segment of a dotted version string."""
    raw = (version or "").strip() or DEFAULT_PROFILE_VERSION
    parts = raw.split(".")
    for index in range(len(parts) - 1, -1, -1):
        segment = parts[index]
        if segment.isdigit():
            parts[index] = str(int(segment) + 1)
            return ".".join(parts)
    return f"{raw}.1"


def normalize_playbook_version(version: str | None) -> str:
    """Return playbook version, mapping leftover catalog values back to 1.0."""
    raw = str(version or "").strip() or DEFAULT_PLAYBOOK_VERSION
    if raw in {"1.0.0", "1.0.1", "1.1.0"}:
        return DEFAULT_PLAYBOOK_VERSION
    return raw


def _find_profile_file(package_dir: Path) -> Path | None:
    description = package_dir / DESCRIPTION_FILE
    if description.is_file():
        return description
    return None


def _load_metadata_file(package_dir: Path, reference: str | None) -> dict | None:
    if not reference:
        return None
    path = package_dir / reference
    if path.is_file():
        return _read_json(path)
    return None


def _resolve_os_software_meta(
    package_dir: Path,
    profile_meta: dict,
) -> tuple[dict | None, dict | None]:
    """Resolve os/software from inline objects or file references."""
    os_val = profile_meta.get("os")
    software_val = profile_meta.get("software")

    os_meta: dict | None = None
    if isinstance(os_val, dict):
        os_meta = os_val
    elif isinstance(os_val, str):
        os_meta = _load_metadata_file(package_dir, os_val)
    if os_meta is None and (package_dir / "os.json").is_file():
        os_meta = _read_json(package_dir / "os.json")

    software_meta: dict | None = None
    if isinstance(software_val, dict):
        software_meta = software_val
    elif isinstance(software_val, str):
        software_meta = _load_metadata_file(package_dir, software_val)
    if software_meta is None and (package_dir / "software.json").is_file():
        software_meta = _read_json(package_dir / "software.json")

    return os_meta, software_meta


def _has_os_metadata(package_dir: Path, profile_meta: dict, os_meta: dict | None) -> bool:
    if os_meta is not None:
        return True
    os_ref = profile_meta.get("os")
    return bool(isinstance(os_ref, str) and (package_dir / os_ref).is_file()) or (
        package_dir / "os.json"
    ).is_file()


def _has_software_metadata(
    package_dir: Path,
    profile_meta: dict,
    software_meta: dict | None,
) -> bool:
    if software_meta is not None:
        return True
    software_ref = profile_meta.get("software")
    return bool(isinstance(software_ref, str) and (package_dir / software_ref).is_file()) or (
        package_dir / "software.json"
    ).is_file()


_NETWORK_OS_TOKENS = (
    "cisco",
    "ios",
    "nx-os",
    "nxos",
    "junos",
    "juniper",
    "mikrotik",
    "routeros",
    "eltex",
    "continent",
    "arista",
    "fortinet",
    "palo alto",
    "huawei",
    "h3c",
    "xiaomi",
    "miwifi",
)


def _looks_like_network_os(haystack: str) -> bool:
    return any(token in haystack for token in _NETWORK_OS_TOKENS)


def infer_category_slug(
    tree_path: str | None,
    os_meta: dict | None,
    software_meta: dict | None,
) -> str:
    """Infer category from os/software metadata.

    ``tree_path`` is retained for callers/tests that pass an explicit value; the
    product no longer reads ``standard-meta.json`` / ``rule_types.json``.
    """
    if tree_path:
        parts = [part.strip().upper() for part in tree_path.split(";") if part.strip()]
        if parts:
            root = parts[0]
            if root == "OS":
                second = parts[1] if len(parts) > 1 else ""
                if "WINDOWS" in second:
                    return "windows-platform"
                return "linux-platform"
            if root == "NETWORK":
                return "network-platform"
            return "services"

    if os_meta:
        haystack = f"{os_meta.get('name', '')} {os_meta.get('vendor', '')}".lower()
        if "windows" in haystack:
            return "windows-platform"
        if _looks_like_network_os(haystack):
            return "network-platform"
        return "linux-platform"

    if software_meta:
        haystack = f"{software_meta.get('name', '')} {software_meta.get('vendor', '')}".lower()
        if _looks_like_network_os(haystack):
            return "network-platform"
        category_label = str(software_meta.get("category", "")).lower()
        if any(token in category_label for token in ("операцион", "operating system", "operating systems")):
            if "windows" in haystack:
                return "windows-platform"
            return "linux-platform"
        return "services"

    return "services"


def _is_excluded_script(path: Path) -> bool:
    lowered = path.name.lower()
    return any(marker in lowered for marker in EXCLUDED_SCRIPT_MARKERS)


def _compliance_playbook_ref(profile_meta: dict | None) -> str | None:
    if not isinstance(profile_meta, dict):
        return None
    value = profile_meta.get(COMPLIANCE_PLAYBOOK_KEY)
    if isinstance(value, str) and value.strip():
        return value.strip().replace("\\", "/").lstrip("/")
    return None


def _looks_like_compliance_playbook_name(name: str) -> bool:
    path = Path(name)
    if path.suffix.lower() not in {".yml", ".yaml"}:
        return False
    return path.stem.lower().endswith("_compliance")


def is_compliance_playbook_file(path: Path, profile_meta: dict | None = None) -> bool:
    """True when a package YAML is the optional compliance playbook (not an audit CheckScript)."""
    ref = _compliance_playbook_ref(profile_meta)
    if ref and path.name == Path(ref).name:
        return True
    return _looks_like_compliance_playbook_name(path.name)


def resolve_compliance_playbook_path(
    package_dir: Path,
    profile_meta: dict | None = None,
) -> Path | None:
    """Resolve optional compliance Ansible playbook inside a profile package."""
    meta = profile_meta
    if meta is None:
        profile_file = _find_profile_file(package_dir)
        if profile_file:
            meta = _read_json(profile_file)

    ref = _compliance_playbook_ref(meta)
    if ref:
        candidate = package_dir / Path(ref).name
        if candidate.is_file():
            return candidate

    matches = sorted(
        [
            path
            for path in package_dir.iterdir()
            if path.is_file() and _looks_like_compliance_playbook_name(path.name)
        ],
        key=lambda item: item.name.lower(),
    )
    return matches[0] if matches else None


def ensure_compliance_playbook_declared(
    package_dir: Path,
    *,
    filename: str | None = None,
    content: str | bytes | None = None,
    version: str | None = None,
) -> Path | None:
    """Write/attach compliance playbook and declare it in description.json when needed.

    Does not rewrite description.json when the declaration is already correct and no
    new content was provided (safe for read-only catalog mounts used as import source).
    """
    profile_file = _find_profile_file(package_dir)
    if not profile_file:
        raise FileNotFoundError("Profile description.json not found")

    profile_meta = _read_json(profile_file)
    target_name = (filename or _compliance_playbook_ref(profile_meta) or "").strip()
    wrote_content = False
    if content is not None:
        if not target_name:
            target_name = "compliance_playbook.yml"
        if not _looks_like_compliance_playbook_name(target_name) and not target_name.lower().endswith(
            (".yml", ".yaml")
        ):
            target_name = f"{Path(target_name).stem}_compliance.yml"
        elif not target_name.lower().endswith((".yml", ".yaml")):
            target_name = f"{target_name}_compliance.yml"
        target = package_dir / Path(target_name).name
        text = content.decode("utf-8") if isinstance(content, (bytes, bytearray)) else str(content)
        target.write_text(text, encoding="utf-8", newline="\n")
        wrote_content = True
    else:
        target = resolve_compliance_playbook_path(package_dir, profile_meta)
        if target is None:
            return None

    meta_changed = False
    if profile_meta.get(COMPLIANCE_PLAYBOOK_KEY) != target.name:
        profile_meta[COMPLIANCE_PLAYBOOK_KEY] = target.name
        meta_changed = True
    if version is not None:
        if str(profile_meta.get(COMPLIANCE_PLAYBOOK_VERSION_KEY) or "").strip() != str(version).strip():
            profile_meta[COMPLIANCE_PLAYBOOK_VERSION_KEY] = version
            meta_changed = True
    elif not str(profile_meta.get(COMPLIANCE_PLAYBOOK_VERSION_KEY) or "").strip():
        profile_meta[COMPLIANCE_PLAYBOOK_VERSION_KEY] = "1.0.0"
        meta_changed = True

    if wrote_content or meta_changed:
        _write_json(profile_file, normalize_description_meta(profile_meta))
    return target


def read_compliance_playbook(package_dir: Path, profile_meta: dict | None = None) -> dict | None:
    """Return compliance playbook payload or None when package has no playbook."""
    path = resolve_compliance_playbook_path(package_dir, profile_meta)
    if path is None:
        return None
    meta = profile_meta
    if meta is None:
        profile_file = _find_profile_file(package_dir)
        meta = _read_json(profile_file) if profile_file else {}
    version = normalize_playbook_version((meta or {}).get(COMPLIANCE_PLAYBOOK_VERSION_KEY))
    return {
        "file": path.name,
        "path": path,
        "version": version,
        "content": path.read_text(encoding="utf-8", errors="replace"),
    }


def load_playbook_changelog(package_dir: Path, *, limit: int | None = None) -> list[dict]:
    """Load package-local compliance playbook changelog (newest first)."""
    path = package_dir / PLAYBOOK_CHANGELOG_JSON
    if not path.is_file():
        return []
    try:
        payload = _read_json(path)
    except (OSError, json.JSONDecodeError, ValueError):
        return []
    entries = payload.get("entries") if isinstance(payload, dict) else None
    if not isinstance(entries, list):
        return []
    cleaned = [item for item in entries if isinstance(item, dict)]
    cleaned.reverse()
    return cleaned[:limit] if limit is not None else cleaned


def _append_playbook_changelog_entry(package_dir: Path, entry: dict) -> None:
    path = package_dir / PLAYBOOK_CHANGELOG_JSON
    if path.is_file():
        try:
            existing = _read_json(path)
            payload = existing if isinstance(existing, dict) else {"version": 1, "entries": []}
        except (OSError, json.JSONDecodeError, ValueError):
            payload = {"version": 1, "entries": []}
    else:
        payload = {"version": 1, "entries": []}
    entries = payload.get("entries")
    if not isinstance(entries, list):
        entries = []
    entries.append(entry)
    payload["version"] = 1
    payload["entries"] = entries
    _write_json(path, payload)


def update_compliance_playbook_in_package(
    package_dir: Path,
    content: str,
    *,
    actor: str | None = None,
) -> dict:
    """Update compliance playbook YAML, bump compliance_playbook_version, append changelog."""
    from datetime import UTC, datetime
    from uuid import uuid4

    new_content = content.replace("\r\n", "\n")
    if not new_content.strip():
        raise ValueError("Playbook content must not be empty")

    profile_file = _find_profile_file(package_dir)
    if not profile_file:
        raise FileNotFoundError("Profile description.json not found")
    profile_meta = _read_json(profile_file)
    playbook_path = resolve_compliance_playbook_path(package_dir, profile_meta)
    if playbook_path is None:
        raise FileNotFoundError("Compliance playbook not found in package")

    old_content = playbook_path.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
    if old_content == new_content:
        raise ValueError("No changes to apply")

    playbook_path.write_text(new_content, encoding="utf-8", newline="\n")
    version_before = normalize_playbook_version(profile_meta.get(COMPLIANCE_PLAYBOOK_VERSION_KEY))
    version_after = bump_semver_patch(version_before)
    profile_meta[COMPLIANCE_PLAYBOOK_KEY] = playbook_path.name
    profile_meta[COMPLIANCE_PLAYBOOK_VERSION_KEY] = version_after
    _write_json(profile_file, profile_meta)

    changelog_entry = {
        "id": str(uuid4()),
        "at": datetime.now(UTC).isoformat(),
        "actor": (actor or "").strip() or None,
        "playbook_version_before": version_before,
        "playbook_version_after": version_after,
        "changes": {"content": {"from": old_content, "to": new_content}},
    }
    _append_playbook_changelog_entry(package_dir, changelog_entry)

    return {
        "file": playbook_path.name,
        "content": new_content,
        "playbook_version": version_after,
        "playbook_version_before": version_before,
        "changes": changelog_entry["changes"],
        "changelog_entry": changelog_entry,
    }


def _rules_ref_from_meta(profile_meta: dict) -> str | None:
    for key in RULES_REF_KEYS:
        value = profile_meta.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def resolve_rules_path(package_dir: Path, profile_meta: dict | None = None) -> Path | None:
    """Resolve the package rules file (profile_rules.json)."""
    meta = profile_meta
    if meta is None:
        profile_file = _find_profile_file(package_dir)
        if not profile_file:
            return None
        meta = _read_json(profile_file)

    rules_ref = _rules_ref_from_meta(meta)
    if rules_ref:
        path = package_dir / rules_ref
        if path.is_file():
            return path

    conventional = package_dir / PROFILE_RULES_JSON
    if conventional.is_file():
        return conventional
    return None


def _rule_field_raw(raw: dict, canonical: str) -> str | None:
    """Read a canonical rule field, accepting documented legacy aliases."""
    value = raw.get(canonical)
    if value is None or (isinstance(value, str) and not value.strip()):
        for alias in RULE_FIELD_ALIASES.get(canonical, ()):
            alias_value = raw.get(alias)
            if alias_value is not None and str(alias_value).strip():
                value = alias_value
                break
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _strip_legacy_rule_fields(raw: dict) -> None:
    for key in LEGACY_RULE_FIELD_KEYS:
        raw.pop(key, None)


def _script_names_from_rules(rules_path: Path) -> set[str]:
    if rules_path.suffix.lower() != ".json":
        return set()
    return {
        str(item.get("check_script") or "").strip()
        for item in _load_rules_records(rules_path)
        if str(item.get("check_script") or "").strip()
    }


def _normalize_rule_record(raw: dict) -> dict | None:
    requirement_id = (
        str(raw.get("requirement_id") or raw.get("script_context_name") or raw.get("tech_name") or "").strip()
    )
    if not requirement_id:
        return None
    # Canonical identity is requirement_id. JSON may omit tech_name/title;
    # derive them so DB/API/interpreter stay compatible.
    tech_name = str(raw.get("tech_name") or requirement_id).strip()
    title = _rule_field_raw(raw, "title")
    match_pattern = _rule_field_raw(raw, "match_pattern")
    extraction = str(raw.get("extraction_type") or raw.get("extractionType") or "SINGLE").strip() or "SINGLE"
    num = raw.get("num")
    return {
        "num": str(num).strip() if num is not None and str(num).strip() else None,
        "tech_name": tech_name,
        "requirement_id": requirement_id,
        "title": title,
        "explanation": _rule_field_raw(raw, "explanation"),
        "impact": _rule_field_raw(raw, "impact"),
        "scope": _rule_field_raw(raw, "scope"),
        "check_script": _rule_field_raw(raw, "check_script"),
        "scap_rule_id": str(raw.get("scap_rule_id") or "").strip() or None,
        "criticality": _rule_field_raw(raw, "criticality"),
        "label": str(raw.get("label") or "").strip() or None,
        "operator": str(raw.get("operator") or "").strip() or None,
        "target_value": str(raw.get("target_value") or "").strip() or None,
        "default_value": str(raw.get("default_value") or "").strip() or None,
        "value_type": str(raw.get("value_type") or "").strip() or None,
        "parser_rule": str(raw.get("parser_rule") or "").strip() or None,
        "security_level": str(raw.get("security_level") or "").strip() or None,
        "rule_type_tech_name": str(raw.get("rule_type_tech_name") or "").strip() or None,
        "mnemonic": str(raw.get("mnemonic") or "").strip() or None,
        "match_pattern": match_pattern,
        "extraction_type": extraction,
    }


def _load_rules_records_from_json(json_path: Path) -> list[dict]:
    payload = _read_json(json_path)
    if isinstance(payload, dict):
        raw_rules = payload.get("rules")
    elif isinstance(payload, list):
        raw_rules = payload
    else:
        raise ValueError(f"Unsupported profile rules JSON structure in {json_path.name}")
    if not isinstance(raw_rules, list):
        raise ValueError(f"profile rules JSON must contain a list of rules: {json_path.name}")

    records: list[dict] = []
    for item in raw_rules:
        if not isinstance(item, dict):
            continue
        normalized = _normalize_rule_record(item)
        if normalized:
            records.append(normalized)
    return records


def _load_rules_records(rules_path: Path) -> list[dict]:
    if rules_path.suffix.lower() != ".json":
        raise ValueError(
            f"Unsupported rules file '{rules_path.name}'; use {PROFILE_RULES_JSON}"
        )
    return _load_rules_records_from_json(rules_path)


def load_profile_rules_metadata(package_dir: Path, *, limit: int | None = None) -> list[dict]:
    """Load check-item metadata from profile_rules.json."""
    profile_file = _find_profile_file(package_dir)
    if not profile_file:
        return []

    profile_meta = _read_json(profile_file)
    rules_path = resolve_rules_path(package_dir, profile_meta)
    if not rules_path or rules_path.suffix.lower() != ".json":
        return []

    rules = [
        {
            "num": item.get("num"),
            "tech_name": item.get("tech_name"),
            "requirement_id": item.get("requirement_id"),
            "title": item.get("title"),
            "explanation": item.get("explanation"),
            "impact": item.get("impact"),
            "scope": item.get("scope"),
            "check_script": item.get("check_script"),
            "scap_rule_id": item.get("scap_rule_id"),
            "criticality": item.get("criticality"),
        }
        for item in _load_rules_records(rules_path)
    ]
    return rules[:limit] if limit is not None else rules


def load_rule_changelog(package_dir: Path, *, limit: int | None = None) -> list[dict]:
    """Load package-local check-item changelog (newest first)."""
    path = package_dir / RULE_CHANGELOG_JSON
    if not path.is_file():
        return []
    try:
        payload = _read_json(path)
    except (OSError, json.JSONDecodeError, ValueError):
        return []
    entries = payload.get("entries") if isinstance(payload, dict) else None
    if not isinstance(entries, list):
        return []
    cleaned = [item for item in entries if isinstance(item, dict)]
    cleaned.reverse()
    return cleaned[:limit] if limit is not None else cleaned


def _append_rule_changelog_entry(package_dir: Path, entry: dict) -> None:
    path = package_dir / RULE_CHANGELOG_JSON
    payload: dict
    if path.is_file():
        try:
            existing = _read_json(path)
            payload = existing if isinstance(existing, dict) else {"version": 1, "entries": []}
        except (OSError, json.JSONDecodeError, ValueError):
            payload = {"version": 1, "entries": []}
    else:
        payload = {"version": 1, "entries": []}
    entries = payload.get("entries")
    if not isinstance(entries, list):
        entries = []
    entries.append(entry)
    payload["version"] = 1
    payload["entries"] = entries
    _write_json(path, payload)


def update_profile_rule_in_package(
    package_dir: Path,
    requirement_id: str,
    updates: dict,
    *,
    actor: str | None = None,
) -> dict:
    """Update editable fields of a rule in profile_rules.json, bump profile version, append changelog.

    Returns dict with keys: rule, profile_version, profile_version_before, changes, changelog_entry.
    """
    from datetime import UTC, datetime
    from uuid import uuid4

    requirement_id = str(requirement_id or "").strip()
    if not requirement_id:
        raise ValueError("requirement_id is required")

    profile_file = _find_profile_file(package_dir)
    if not profile_file:
        raise FileNotFoundError("Profile description.json not found")

    profile_meta = _read_json(profile_file)
    rules_path = resolve_rules_path(package_dir, profile_meta)
    if not rules_path:
        raise FileNotFoundError("profile_rules.json not found")
    if rules_path.suffix.lower() != ".json":
        raise ValueError("Only JSON profile_rules can be edited")

    payload = _read_json(rules_path)
    if isinstance(payload, dict):
        raw_rules = payload.get("rules")
    elif isinstance(payload, list):
        raw_rules = payload
        payload = {"version": 1, "format": "secaudit.profile_rules", "rules": raw_rules}
    else:
        raise ValueError(f"Unsupported profile rules JSON structure in {rules_path.name}")
    if not isinstance(raw_rules, list):
        raise ValueError(f"profile rules JSON must contain a list of rules: {rules_path.name}")

    target_index: int | None = None
    target_raw: dict | None = None
    for index, item in enumerate(raw_rules):
        if not isinstance(item, dict):
            continue
        rid = str(
            item.get("requirement_id") or item.get("script_context_name") or item.get("tech_name") or ""
        ).strip()
        if rid == requirement_id:
            target_index = index
            target_raw = item
            break
    if target_index is None or target_raw is None:
        raise LookupError(f"Rule '{requirement_id}' not found")

    changes: dict[str, dict[str, str | None]] = {}
    for field in EDITABLE_RULE_FIELDS:
        if field not in updates:
            continue
        new_value = updates[field]
        if new_value is None:
            normalized_new: str | None = None
        else:
            normalized_new = str(new_value).strip() or None
        old_value = _rule_field_raw(target_raw, field)
        if old_value == normalized_new:
            continue
        if normalized_new is None:
            target_raw.pop(field, None)
        else:
            target_raw[field] = normalized_new
        for alias in RULE_FIELD_ALIASES.get(field, ()):
            target_raw.pop(alias, None)
        changes[field] = {"from": old_value, "to": normalized_new}

    if not changes:
        raise ValueError("No changes to apply")

    _strip_legacy_rule_fields(target_raw)
    raw_rules[target_index] = target_raw
    payload["rules"] = raw_rules
    _write_json(rules_path, payload)

    version_before = str(profile_meta.get("version") or DEFAULT_PROFILE_VERSION).strip() or DEFAULT_PROFILE_VERSION
    version_after = bump_semver_patch(version_before)
    profile_meta["version"] = version_after
    _write_json(profile_file, profile_meta)

    changelog_entry = {
        "id": str(uuid4()),
        "at": datetime.now(UTC).isoformat(),
        "actor": (actor or "").strip() or None,
        "requirement_id": requirement_id,
        "profile_version_before": version_before,
        "profile_version_after": version_after,
        "changes": changes,
    }
    _append_rule_changelog_entry(package_dir, changelog_entry)

    normalized = _normalize_rule_record(target_raw)
    if not normalized:
        raise ValueError("Updated rule is invalid")

    return {
        "rule": {
            "num": normalized.get("num"),
            "tech_name": normalized.get("tech_name"),
            "requirement_id": normalized.get("requirement_id"),
            "title": normalized.get("title"),
            "explanation": normalized.get("explanation"),
            "impact": normalized.get("impact"),
            "scope": normalized.get("scope"),
            "check_script": normalized.get("check_script"),
            "scap_rule_id": normalized.get("scap_rule_id"),
            "criticality": normalized.get("criticality"),
        },
        "profile_version": version_after,
        "profile_version_before": version_before,
        "changes": changes,
        "changelog_entry": changelog_entry,
    }


def _interpreter_rules_for_script(rules_path: Path, script_name: str) -> list[dict]:
    rules: list[dict] = []
    for item in _load_rules_records(rules_path):
        if (item.get("check_script") or "") != script_name:
            continue
        pattern = item.get("match_pattern")
        tech_name = item.get("requirement_id") or item.get("tech_name")
        if not pattern or not tech_name:
            continue
        rules.append(
            {
                "regex": pattern,
                "extractionType": item.get("extraction_type") or "SINGLE",
                "techName": tech_name,
            }
        )
    return rules


def _is_remediation_script(path: Path) -> bool:
    lowered = path.name.lower()
    return REMEDIATION_SCRIPT_MARKER in lowered and path.suffix.lower() in SCRIPT_EXTENSIONS


def discover_remediation_scripts(package_dir: Path) -> list[dict]:
    scripts: list[dict] = []
    candidates: list[Path] = []
    for path in sorted(package_dir.iterdir()):
        if path.is_file():
            candidates.append(path)
    scripts_dir = package_dir / "scripts"
    if scripts_dir.is_dir():
        for path in sorted(scripts_dir.iterdir()):
            if path.is_file():
                candidates.append(path)

    seen_names: set[str] = set()
    for path in candidates:
        if not _is_remediation_script(path):
            continue
        stem = path.stem
        if stem in seen_names:
            continue
        seen_names.add(stem)
        execution_type = SCRIPT_EXTENSIONS.get(path.suffix.lower(), ExecutionType.SSH)
        script_file = path.name if path.parent == package_dir else str(path.relative_to(package_dir))
        scripts.append(
            {
                "name": stem,
                "type": execution_type.value.upper(),
                "script_file": script_file.replace("\\", "/"),
                "description": None,
            }
        )
    return scripts


def infer_category_from_package_dir(package_dir: Path) -> str:
    """Infer platform category slug from package metadata without full validation."""
    profile_file = _find_profile_file(package_dir)
    if not profile_file:
        return "services"

    profile_meta = _read_json(profile_file)
    os_meta, software_meta = _resolve_os_software_meta(package_dir, profile_meta)
    return infer_category_slug(None, os_meta, software_meta)


def read_package_text_file(path: Path, *, encoding_hint: str | None = None) -> str:
    """Read a package text file, tolerating legacy Windows encodings in script comments."""
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {path.name}")

    from secaudit_core.package_paths import normalize_text_newlines

    raw = path.read_bytes()
    candidates: list[str] = []
    if encoding_hint:
        candidates.append(encoding_hint.strip())
    candidates.extend(["utf-8", "cp1252", "latin-1"])

    seen: set[str] = set()
    text: str | None = None
    for encoding in candidates:
        key = encoding.lower()
        if key in seen:
            continue
        seen.add(key)
        try:
            text = raw.decode(encoding)
            break
        except UnicodeDecodeError:
            continue

    if text is None:
        text = raw.decode("utf-8", errors="replace")
    return normalize_text_newlines(text)


def package_encoding_hint(package_dir: Path) -> str | None:
    profile_file = _find_profile_file(package_dir)
    if not profile_file:
        return None
    profile_meta = normalize_description_meta(_read_json(profile_file))
    encoding = profile_meta.get("encoding")
    return str(encoding).strip() if encoding else None


# Backward-compatible alias
package_charset_hint = package_encoding_hint


def discover_check_scripts(package_dir: Path, profile_meta: dict) -> list[dict]:
    allowed_names: set[str] | None = None
    rules_path = resolve_rules_path(package_dir, profile_meta)
    if rules_path:
        allowed_names = _script_names_from_rules(rules_path)

    scripts: list[dict] = []
    for path in sorted(package_dir.iterdir()):
        if not path.is_file() or _is_excluded_script(path) or _is_remediation_script(path):
            continue
        if is_compliance_playbook_file(path, profile_meta):
            continue
        execution_type = SCRIPT_EXTENSIONS.get(path.suffix.lower())
        if execution_type is None:
            continue
        stem = path.stem
        if allowed_names is not None and stem not in allowed_names:
            continue
        scripts.append(
            {
                "name": stem,
                "type": execution_type.value.upper(),
                "script_file": path.name,
                "description": None,
            }
        )

    return scripts


def _attach_rules_to_scripts(package_dir: Path, profile_meta: dict, scripts: list[dict]) -> list[dict]:
    rules_path = resolve_rules_path(package_dir, profile_meta)
    enriched: list[dict] = []
    for script in scripts:
        context: list[dict] = []
        if rules_path:
            context = _interpreter_rules_for_script(rules_path, script["name"])
        enriched.append({**script, "context": context})
    return enriched


def _require_referenced_file(package_dir: Path, reference: str | None, label: str) -> None:
    if not reference:
        return
    path = package_dir / reference
    if not path.is_file():
        raise FileNotFoundError(f"{label} file not found: {reference}")


def _validate_rule_regexes(rules: list[dict], source: str, script_name: str) -> None:
    for rule in rules:
        try:
            re.compile(rule["regex"], re.MULTILINE)
        except re.error as exc:
            tech_name = rule.get("techName") or rule.get("tech_name") or "?"
            raise ValueError(
                f"Invalid regex in {source} for script '{script_name}' "
                f"(rule '{tech_name}'): {exc}"
            ) from exc


def _validate_rules_coverage(
    package_dir: Path,
    profile_meta: dict,
    scripts: list[dict],
) -> None:
    rules_ref = _rules_ref_from_meta(profile_meta)
    rules_path = resolve_rules_path(package_dir, profile_meta)
    if not rules_path:
        raise ValueError(
            "Profile description must reference rules via profile_rules "
            f"or {PROFILE_RULES_JSON}"
        )
    if rules_path.suffix.lower() != ".json":
        raise ValueError(
            f"Unsupported rules file '{rules_path.name}'; use {PROFILE_RULES_JSON}"
        )
    _require_referenced_file(package_dir, rules_ref or rules_path.name, "Rules")
    for script in scripts:
        rules = _interpreter_rules_for_script(rules_path, script["name"])
        if not rules:
            raise ValueError(
                f"No rules found in {rules_path.name} for script '{script['name']}'"
            )
        _validate_rule_regexes(rules, rules_path.name, script["name"])


def package_is_catalog_candidate(package_dir: Path) -> bool:
    """Fast structural check for catalog listing (skips regex deep validation)."""
    if not package_dir.is_dir():
        return False

    profile_file = _find_profile_file(package_dir)
    if not profile_file:
        return False

    try:
        profile_meta = _read_json(profile_file)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return False

    os_meta, software_meta = _resolve_os_software_meta(package_dir, profile_meta)
    if not _has_os_metadata(package_dir, profile_meta, os_meta) and not _has_software_metadata(
        package_dir, profile_meta, software_meta
    ):
        return False

    rules_path = resolve_rules_path(package_dir, profile_meta)
    if not rules_path:
        return False

    has_script = False
    for path in package_dir.iterdir():
        if not path.is_file() or _is_excluded_script(path) or _is_remediation_script(path):
            continue
        if path.suffix.lower() in SCRIPT_EXTENSIONS:
            has_script = True
            break
    if not has_script:
        return False

    return True


def validate_profile_package(package_dir: Path) -> None:
    if not package_dir.is_dir():
        raise FileNotFoundError(f"Profile package directory not found: {package_dir}")

    profile_file = _find_profile_file(package_dir)
    if not profile_file:
        raise FileNotFoundError(f"Profile description file ({DESCRIPTION_FILE}) is required")

    profile_meta = _read_json(profile_file)

    os_ref = profile_meta.get("os")
    if isinstance(os_ref, str):
        _require_referenced_file(package_dir, os_ref, "OS metadata")
    software_ref = profile_meta.get("software")
    if isinstance(software_ref, str):
        _require_referenced_file(package_dir, software_ref, "Software metadata")

    os_meta, software_meta = _resolve_os_software_meta(package_dir, profile_meta)
    if not _has_os_metadata(package_dir, profile_meta, os_meta) and not _has_software_metadata(
        package_dir, profile_meta, software_meta
    ):
        raise FileNotFoundError(
            "At least one metadata block (os or software) is required in the package description"
        )

    rules_ref = _rules_ref_from_meta(profile_meta)
    rules_path = resolve_rules_path(package_dir, profile_meta)
    if rules_ref and not rules_path:
        raise FileNotFoundError(f"Rules file not found: {rules_ref}")
    if rules_path and rules_path.suffix.lower() != ".json":
        raise ValueError(
            f"Unsupported rules file '{rules_path.name}'; use {PROFILE_RULES_JSON}"
        )

    scripts = discover_check_scripts(package_dir, profile_meta)
    if not scripts:
        if rules_path:
            expected = sorted(_script_names_from_rules(rules_path))
            if expected:
                raise FileNotFoundError(
                    "No check scripts match script_name entries in "
                    f"{rules_path.name}. Expected script stem(s): {', '.join(expected)}"
                )
        raise FileNotFoundError("At least one check script (*.sh, *.py, *.ps1) is required")

    _validate_rules_coverage(package_dir, profile_meta, scripts)


def load_profile_package(package_dir: Path) -> dict:
    """Load profile metadata, scripts, and inferred category from a package directory."""
    validate_profile_package(package_dir)

    profile_file = _find_profile_file(package_dir)
    assert profile_file is not None
    profile_meta = normalize_description_meta(_read_json(profile_file))
    os_meta, software_meta = _resolve_os_software_meta(package_dir, profile_meta)
    explicit_slug = profile_meta.get("category_slug")
    category_slug = (
        str(explicit_slug).strip()
        if isinstance(explicit_slug, str) and explicit_slug.strip()
        else infer_category_slug(None, os_meta, software_meta)
    )

    scripts = discover_check_scripts(package_dir, profile_meta)
    scripts = _attach_rules_to_scripts(package_dir, profile_meta, scripts)

    return {
        "profile": profile_meta,
        "scripts": scripts,
        "remediation_scripts": discover_remediation_scripts(package_dir),
        "category_slug": category_slug,
    }


def package_structure_signature(package_dir: Path) -> str:
    """Stable signature of package layout (files + rule script bindings + playbook ref).

    Used by catalog sync to refresh imported profiles when scripts/playbooks are renamed
    without a version bump.
    """
    import hashlib

    if not package_dir.is_dir():
        return ""

    file_names: list[str] = []
    for path in sorted(package_dir.iterdir(), key=lambda item: item.name.lower()):
        if not path.is_file():
            continue
        name = path.name
        if name.startswith(".") or name == "Thumbs.db":
            continue
        file_names.append(name)

    script_names: list[str] = []
    rules_path = package_dir / PROFILE_RULES_JSON
    if rules_path.is_file():
        try:
            payload = _read_json(rules_path)
            rules = payload.get("rules") if isinstance(payload, dict) else None
            if isinstance(rules, list):
                for rule in rules:
                    if not isinstance(rule, dict):
                        continue
                    sn = str(rule.get("check_script") or rule.get("script_name") or "").strip()
                    if sn:
                        script_names.append(sn)
        except (OSError, ValueError, TypeError):
            pass

    playbook = ""
    profile_file = _find_profile_file(package_dir)
    if profile_file:
        try:
            meta = normalize_description_meta(_read_json(profile_file))
            ref = meta.get(COMPLIANCE_PLAYBOOK_KEY)
            if isinstance(ref, str):
                playbook = ref.strip().replace("\\", "/").lstrip("/")
        except (OSError, ValueError, TypeError):
            pass

    payload = "\n".join(
        [
            "files:" + ",".join(file_names),
            "script_names:" + ",".join(sorted(set(script_names))),
            "playbook:" + playbook,
        ]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


