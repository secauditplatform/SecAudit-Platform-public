"""Pick the profile's active scripts: one audit and one remediation script, never more."""

from __future__ import annotations

from typing import TypeVar

T = TypeVar("T")


def select_active_scripts(scripts: list[T]) -> list[T]:
    """Return the active scripts, or every script when none is marked.

    A profile has at most one active script per kind, so this never runs several at once.
    The fallback keeps profiles imported before the selection existed working.
    """
    primaries = [script for script in scripts if getattr(script, "is_primary", False)]
    return primaries or list(scripts)
