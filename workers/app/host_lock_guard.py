"""Acquire/release cross-run host locks around compliance/remediation work."""

from __future__ import annotations

import logging
from collections.abc import Callable
from contextlib import contextmanager
from typing import Iterator, TypeVar

from secaudit_core.host_lock import acquire_host_lock, release_host_lock
from secaudit_core.preflight import tcp_reachable
from secaudit_core.run_cancel import is_run_cancel_requested
from secaudit_core.settings import SecAuditSettings

from app.cancel_context import get_active_run, is_cancelled

logger = logging.getLogger(__name__)

T = TypeVar("T")
HostT = TypeVar("HostT")


def host_tcp_ready(host: HostT, *, timeout: float = 3.0) -> tuple[bool, str]:
    """Cheap reachability gate before queueing for the host lock."""
    hostname = str(getattr(host, "hostname", "") or "").strip()
    try:
        port = int(getattr(host, "port", None) or 22)
    except (TypeError, ValueError):
        port = 22
    return tcp_reachable(hostname, port, timeout=timeout)


def _abort_lock_wait(settings: SecAuditSettings) -> bool:
    if is_cancelled():
        return True
    active = get_active_run()
    if active is None:
        return False
    try:
        return is_run_cancel_requested(settings.redis_url, active[0], active[1])
    except Exception:
        return False


@contextmanager
def hold_host_lock(
    settings: SecAuditSettings,
    host_id: int,
    *,
    label: str,
) -> Iterator[bool]:
    """Yield True when lock acquired; False when queue wait expired or cancelled."""
    client, token = acquire_host_lock(
        settings.redis_url,
        host_id,
        ttl_seconds=settings.host_lock_ttl_seconds,
        wait_seconds=settings.host_lock_wait_effective,
        should_abort=lambda: _abort_lock_wait(settings),
    )
    if token is None:
        if _abort_lock_wait(settings):
            logger.info("Host %s lock wait aborted (%s); run cancelled", host_id, label)
        else:
            logger.info("Host %s still busy after queue (%s); lock not acquired", host_id, label)
        yield False
        return
    try:
        yield True
    finally:
        release_host_lock(client, host_id, token)


def wrap_process_host(
    settings: SecAuditSettings,
    process_host: Callable[[HostT], T],
    *,
    label: str,
    on_busy: Callable[[HostT], T],
    on_unreachable: Callable[[HostT, str], T] | None = None,
) -> Callable[[HostT], T]:
    """Per-host worker: reachability → queue for lock → run (or busy/unreachable handler)."""

    def wrapped(host: HostT) -> T:
        if on_unreachable is not None:
            ok, detail = host_tcp_ready(host)
            if not ok:
                logger.info(
                    "Host %s unreachable before %s: %s",
                    getattr(host, "id", "?"),
                    label,
                    detail,
                )
                return on_unreachable(host, detail)
        host_id = int(getattr(host, "id"))
        with hold_host_lock(settings, host_id, label=label) as acquired:
            if not acquired:
                if _abort_lock_wait(settings):
                    raise InterruptedError("Job run cancelled")
                return on_busy(host)
            return process_host(host)

    return wrapped
