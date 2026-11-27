"""Role helpers for SecAudit RBAC."""

from __future__ import annotations

from secaudit_core.enums import UserRole

OPERATE_ROLES: tuple[UserRole, ...] = (UserRole.ADMIN, UserRole.OPERATOR)
REPORTS_ROLES: tuple[UserRole, ...] = (
    UserRole.ADMIN,
    UserRole.OPERATOR,
    UserRole.AUDITOR,
    UserRole.SECURITY_APPROVER,
)
REMEDIATION_ROLES: tuple[UserRole, ...] = (UserRole.ADMIN,)
SCRIPT_ROLES: tuple[UserRole, ...] = (UserRole.ADMIN,)
ADMIN_ROLES: tuple[UserRole, ...] = (UserRole.ADMIN,)

LEGACY_OPERATOR_ROLES = frozenset({"engineer", "viewer"})


def normalize_roles(roles: list[str]) -> list[str]:
    """Map removed roles to operator for backwards-compatible tokens."""
    normalized: list[str] = []
    for role in roles:
        if role in LEGACY_OPERATOR_ROLES:
            if UserRole.OPERATOR.value not in normalized:
                normalized.append(UserRole.OPERATOR.value)
            continue
        normalized.append(role)
    return normalized
