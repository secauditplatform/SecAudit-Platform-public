"""Object-level RBAC: operators and admins see all owned resources."""

from __future__ import annotations

from secaudit_core.enums import UserRole


def applies_engineer_scope(roles: list[str], *, enabled: bool = True) -> bool:
    """Engineer scope removed; always returns False."""
    return False


def can_access_owned_resource(
    roles: list[str],
    user_sub: str,
    owner_sub: str | None,
    *,
    enabled: bool = True,
) -> bool:
    if not applies_engineer_scope(roles, enabled=enabled):
        return True
    return owner_sub is not None and owner_sub == user_sub


def ownership_sub_for_create(user_sub: str) -> str:
    return user_sub
