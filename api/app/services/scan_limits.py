"""Resolve inventory/AuditFlow scan size limits from settings and caller role."""

from __future__ import annotations

from app.core.auth import AuthUser
from app.core.config import settings
from secaudit_core.enums import UserRole
from secaudit_core.inventory_scan import (
    MAX_CIDR_PREFIX_LEN,
    MIN_CIDR_PREFIX_LEN_ABSOLUTE,
)


def resolve_max_cidr_prefix_len(user: AuthUser | None = None) -> int:
    """Return the minimum allowed IPv4 prefix length for this caller.

    Smaller prefix numbers mean larger networks. Operators use the default
    (``inventory_max_cidr_prefix_len``, typically /20). Admins may use a
    wider ceiling (``inventory_max_cidr_prefix_len_admin``, typically /16).
    An absolute floor of /8 always applies in the core validator.
    """
    default = int(getattr(settings, "inventory_max_cidr_prefix_len", MAX_CIDR_PREFIX_LEN) or MAX_CIDR_PREFIX_LEN)
    admin_limit = int(
        getattr(settings, "inventory_max_cidr_prefix_len_admin", default) or default
    )
    # Admin ceiling must not be stricter than the operator default.
    admin_limit = min(admin_limit, default)
    # Never wider than the absolute safety floor.
    default = max(default, MIN_CIDR_PREFIX_LEN_ABSOLUTE)
    admin_limit = max(admin_limit, MIN_CIDR_PREFIX_LEN_ABSOLUTE)

    if user is not None and user.has_role(UserRole.ADMIN):
        return admin_limit
    return default
