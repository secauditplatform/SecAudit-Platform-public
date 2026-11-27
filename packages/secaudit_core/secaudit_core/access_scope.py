"""Operator limits taken from a user record or from Keycloak groups."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class AccessScope:
    sites: tuple[str, ...] = ()
    environments: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()

    @property
    def restricted(self) -> bool:
        return bool(self.sites or self.environments or self.tags)


def clean_scope_values(values: list[str] | None, *, limit: int = 64) -> list[str]:
    cleaned: list[str] = []
    seen: set[str] = set()
    for raw in values or []:
        item = str(raw).strip()
        if not item or item in seen:
            continue
        if len(item) > limit:
            raise ValueError(item)
        seen.add(item)
        cleaned.append(item)
    return cleaned


def scope_from_labels(labels: list[str]) -> AccessScope:
    """Read secaudit:site:, secaudit:env:, and secaudit:tag: labels."""
    sites: list[str] = []
    environments: list[str] = []
    tags: list[str] = []
    for raw in labels:
        label = str(raw).strip().lstrip("/")
        kind, _, value = label.partition(":")
        if kind == "secaudit":
            kind, _, value = value.partition(":")
        value = value.strip()
        if not value or len(value) > 64:
            continue
        if kind == "site" and value not in sites:
            sites.append(value)
        elif kind == "env" and value not in environments:
            environments.append(value)
        elif kind == "tag" and value not in tags:
            tags.append(value)
    return AccessScope(tuple(sites), tuple(environments), tuple(tags))
