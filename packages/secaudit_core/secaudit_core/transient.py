"""Classify transient infrastructure errors for Celery autoretry."""

from __future__ import annotations

from secaudit_core.celery_reliability import (
    TRANSIENT_TASK_EXCEPTIONS,
    TransientOSError,
    is_transient_oserror,
)


def is_transient_error(exc: BaseException) -> bool:
    """Return True for infra errors that should trigger Celery autoretry."""
    if isinstance(exc, InterruptedError):
        return False
    # Check typed exceptions before OSError — ConnectionError/TimeoutError are OSError subclasses.
    if isinstance(exc, TRANSIENT_TASK_EXCEPTIONS):
        return True
    if isinstance(exc, OSError):
        return is_transient_oserror(exc)
    return False


def reraise_if_transient(exc: BaseException) -> None:
    """Re-raise transient exceptions so Celery ``autoretry_for`` can see them."""
    if isinstance(exc, InterruptedError):
        return
    if isinstance(exc, TRANSIENT_TASK_EXCEPTIONS):
        raise exc
    if isinstance(exc, OSError):
        if is_transient_oserror(exc):
            raise TransientOSError(exc.errno, exc.strerror) from exc
        return
