"""Parse rule scope paths and store/restore encrypted remediation backups."""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from secaudit_core.secrets import decrypt_secret, encrypt_secret
from secaudit_core.settings import SecAuditSettings

_REGISTRY_PREFIX = re.compile(r"^(HKLM|HKCU|HKCR|HKU|HKCC|HKEY_[A-Z_]+):", re.I)


@dataclass(frozen=True)
class BackupTarget:
    kind: str  # file | registry
    path_or_key: str


def parse_scope_paths(scope: str | None) -> list[BackupTarget]:
    """Split scope/location into file vs registry targets. Empty scope → []."""
    text = (scope or "").strip()
    if not text:
        return []
    parts = re.split(r"[\n,;]+", text)
    targets: list[BackupTarget] = []
    seen: set[str] = set()
    for part in parts:
        item = part.strip()
        if not item or item in seen:
            continue
        seen.add(item)
        kind = "registry" if _REGISTRY_PREFIX.match(item) else "file"
        targets.append(BackupTarget(kind=kind, path_or_key=item))
    return targets


def scopes_for_rules(rule_meta: list[dict], rule_tech_names: list[str] | None) -> list[BackupTarget]:
    """Collect unique backup targets from selected rules' scope/location."""
    allowed = {name.strip() for name in (rule_tech_names or []) if name and str(name).strip()}
    targets: list[BackupTarget] = []
    seen: set[tuple[str, str]] = set()
    for item in rule_meta:
        tech = str(item.get("requirement_id") or item.get("tech_name") or item.get("id") or "").strip()
        if allowed and tech not in allowed:
            continue
        scope = item.get("scope") or item.get("location") or ""
        for target in parse_scope_paths(str(scope) if scope is not None else ""):
            key = (target.kind, target.path_or_key)
            if key in seen:
                continue
            seen.add(key)
            targets.append(target)
    return targets


def store_backup_bytes(
    payload: bytes,
    *,
    settings: SecAuditSettings,
    run_id: int,
    host_id: int,
    path_key: str,
) -> tuple[str | None, str | None, str, int]:
    """Encrypt payload. Small → DB blob; large → ciphertext file. Returns blob, ref, sha, size."""
    digest = hashlib.sha256(payload).hexdigest()
    size = len(payload)
    max_bytes = max(64 * 1024, int(getattr(settings, "remediation_backup_max_bytes", 2 * 1024 * 1024)))
    if size > max_bytes:
        raise ValueError(f"Backup exceeds {max_bytes} bytes for {path_key}")
    token = encrypt_secret(base64.b64encode(payload).decode("ascii"), settings)
    # Prefer DB under 256 KiB; otherwise write ciphertext beside profiles volume.
    if size <= 256 * 1024:
        return token, None, digest, size
    root = Path(getattr(settings, "remediation_backups_path", "/data/profiles/remediation_backups"))
    folder = root / str(run_id) / str(host_id)
    folder.mkdir(parents=True, exist_ok=True)
    safe = re.sub(r"[^\w.\-]+", "_", path_key)[:180] or "blob"
    ref = folder / f"{digest[:16]}_{safe}.bin"
    ref.write_text(token, encoding="utf-8")
    return None, str(ref), digest, size


def load_backup_bytes(
    *,
    encrypted_blob: str | None,
    storage_ref: str | None,
    settings: SecAuditSettings,
) -> bytes:
    token = encrypted_blob
    if not token and storage_ref:
        token = Path(storage_ref).read_text(encoding="utf-8")
    if not token:
        raise ValueError("Backup artifact is empty")
    return base64.b64decode(decrypt_secret(token, settings))


def ticket_envs(settings: SecAuditSettings) -> set[str]:
    raw = getattr(settings, "remediation_require_ticket_envs", "prod") or ""
    return {part.strip().lower() for part in raw.split(",") if part.strip()}
