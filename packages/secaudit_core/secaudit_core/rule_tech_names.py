"""Stable rule tech-name length and collision helpers."""

from __future__ import annotations

from collections.abc import Iterable

RULE_TECH_NAME_MAX = 256


def allocate_rule_tech_name(base: str, seen: set[str], *, max_len: int = RULE_TECH_NAME_MAX) -> str:
    """Return a unique tech_name within ``max_len``, appending ``_2``, ``_3``, … on collision."""
    cleaned = str(base).strip()
    if not cleaned:
        raise ValueError("empty rule tech_name")
    tech_name = cleaned[:max_len]
    if tech_name not in seen:
        seen.add(tech_name)
        return tech_name
    suffix = 2
    while True:
        marker = f"_{suffix}"
        candidate = f"{cleaned[: max_len - len(marker)]}{marker}"
        if candidate not in seen:
            seen.add(candidate)
            return candidate
        suffix += 1


def excluded_by_version_entries(
    *,
    all_rule_tech_names: Iterable[str],
    requirement_ids: Iterable[str] | None,
    version_label: str | None,
) -> list[dict[str, str | None]]:
    """Rules present on the profile but not selected in the active ProfileVersion.

    Not the same as runtime SKIP / XCCDF notselected.
    """
    allowed = {str(item).strip() for item in (requirement_ids or []) if str(item).strip()}
    label = str(version_label).strip() if version_label else None
    if label == "":
        label = None
    excluded: list[dict[str, str | None]] = []
    for name in sorted({str(item).strip() for item in all_rule_tech_names if str(item).strip()}):
        if name in allowed:
            continue
        # Legacy rows truncated tech_name to 64 while requirement_ids kept the full id.
        if any(name == allowed_id or name == allowed_id[:64] or allowed_id == name[:64] for allowed_id in allowed):
            continue
        excluded.append({"rule_tech_name": name, "version_label": label})
    return excluded
