"""Demo-stand content operators (full mutate/execute while DEMO_MODE is on)."""

from __future__ import annotations

from app.core.config import settings


def demo_operator_usernames() -> set[str]:
    raw = (settings.demo_operator_usernames or "").strip()
    if not raw:
        return set()
    return {part.strip().lower() for part in raw.split(",") if part.strip()}


def is_demo_operator_username(username: str | None) -> bool:
    if not username:
        return False
    return username.strip().lower() in demo_operator_usernames()


def hide_demo_operators_from_actor(actor_username: str | None) -> bool:
    """Guests on the demo stand must not see or mutate content-operator accounts."""
    return settings.demo_mode and not is_demo_operator_username(actor_username)
