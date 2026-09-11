"""Shared Celery reliability constants."""

import errno

from sqlalchemy.exc import OperationalError


class TransientOSError(OSError):
    """Network-related OSError that Celery may safely autoretry."""


# Errnos that indicate transient network/transport failures (not local FS/perms).
TRANSIENT_OS_ERRNOS: frozenset[int] = frozenset(
    {
        errno.ECONNRESET,
        errno.ECONNREFUSED,
        errno.ECONNABORTED,
        errno.ETIMEDOUT,
        errno.EHOSTUNREACH,
        errno.ENETUNREACH,
        errno.ENETDOWN,
        errno.ENETRESET,
        errno.EPIPE,
        errno.ENOTCONN,
        errno.EAGAIN,
        getattr(errno, "EWOULDBLOCK", errno.EAGAIN),
        getattr(errno, "WSAETIMEDOUT", errno.ETIMEDOUT),
        getattr(errno, "WSAECONNRESET", errno.ECONNRESET),
        getattr(errno, "WSAECONNREFUSED", errno.ECONNREFUSED),
    }
)


def is_transient_oserror(exc: OSError) -> bool:
    err = exc.errno
    if err is None:
        return False
    return err in TRANSIENT_OS_ERRNOS


# Exceptions safe to autoretry — transient infra only (not business logic).
TRANSIENT_TASK_EXCEPTIONS: tuple[type[BaseException], ...] = (
    ConnectionError,
    TimeoutError,
    TransientOSError,
    OperationalError,
)

STALE_RUN_ERROR_MESSAGE = "Run timed out or worker lost"
PENDING_ORPHAN_ERROR_MESSAGE = "Run was never picked up by a worker"
WORKER_LOST_ERROR_MESSAGE = "Worker lost during execution; start a new run"

# Shared autoretry policy for worker tasks (compliance, remediation, inventory).
TASK_RETRY_KWARGS: dict[str, object] = {
    "autoretry_for": TRANSIENT_TASK_EXCEPTIONS,
    "retry_backoff": True,
    "retry_backoff_max": 600,
    "max_retries": 3,
}
