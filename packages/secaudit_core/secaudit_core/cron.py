"""Cron expression validation helpers."""


def validate_cron_expression(value: str | None) -> str | None:
    """Return a trimmed cron expression or None; raise ValueError when invalid."""
    if value is None:
        return None
    trimmed = value.strip()
    if not trimmed:
        return None
    try:
        from croniter import croniter

        croniter(trimmed)
    except (ValueError, KeyError) as exc:
        raise ValueError(f"Invalid cron expression: {exc}") from exc
    return trimmed
