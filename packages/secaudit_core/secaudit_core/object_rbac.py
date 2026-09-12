"""Object-level RBAC: non-admin users are limited to owned (and shared) resources."""

from __future__ import annotations

from secaudit_core.enums import UserRole


def applies_owner_scope(roles: list[str], *, enabled: bool = True) -> bool:
    """True when the caller must be limited to owned/shared objects.

    Admins are never scoped. When ``enabled`` is false, nobody is scoped
    (legacy shared-trust mode).
    """
    if not enabled:
        return False
    if UserRole.ADMIN.value in set(roles):
        return False
    return True


def applies_engineer_scope(roles: list[str], *, enabled: bool = True) -> bool:
    """Backward-compatible alias for :func:`applies_owner_scope`."""
    return applies_owner_scope(roles, enabled=enabled)


def can_access_owned_resource(
    roles: list[str],
    user_sub: str,
    owner_sub: str | None,
    *,
    enabled: bool = True,
    mutate: bool = False,
) -> bool:
    """Allow access for admins / unscoped users, owners, and platform-shared (NULL) rows.

    Platform-shared rows (``owner_sub is None``) are readable by scoped users but
    only admins may mutate them.
    """
    if not applies_owner_scope(roles, enabled=enabled):
        return True
    if owner_sub is None:
        return not mutate
    return owner_sub == user_sub


def ownership_sub_for_create(user_sub: str) -> str:
    return user_sub
