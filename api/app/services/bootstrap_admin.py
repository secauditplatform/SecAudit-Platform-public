"""Opt-in first-admin bootstrap for local DB users (Users UI).

Creates a single admin row when the users table is empty and
``BOOTSTRAP_ADMIN_USERNAME`` + password are configured. Never seeds
hardcoded ``dev``/``dev`` credentials.
"""

from __future__ import annotations

import logging

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.passwords import hash_password
from app.models import User, UserRole

logger = logging.getLogger(__name__)


async def maybe_bootstrap_admin(session: AsyncSession) -> bool:
    """Create the first local admin if configured and no users exist yet."""
    username = (settings.bootstrap_admin_username or "").strip()
    password = settings.get_bootstrap_admin_password()
    if not username and not password and not settings.bootstrap_admin_password_file:
        return False

    settings.validate_bootstrap_admin_security()
    assert password is not None  # validated above

    result = await session.execute(select(func.count()).select_from(User))
    existing = int(result.scalar_one())
    if existing > 0:
        logger.info("Bootstrap admin skipped: %s user(s) already exist", existing)
        return False

    email = (settings.bootstrap_admin_email or "").strip() or f"{username}@localhost"
    user = User(
        username=username,
        email=email,
        full_name=None,
        role=UserRole.ADMIN,
        hashed_password=hash_password(password),
        is_active=True,
    )
    session.add(user)
    await session.flush()
    logger.warning(
        "Bootstrapped local admin user %r (id=%s). "
        "Unset BOOTSTRAP_ADMIN_* after first login and manage users via the Users UI.",
        username,
        user.id,
    )
    return True
