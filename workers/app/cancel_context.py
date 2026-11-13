"""Cooperative cancellation token shared across host-parallel workers."""

from __future__ import annotations

import threading
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator

_cancel_event: ContextVar[threading.Event | None] = ContextVar("secaudit_cancel_event", default=None)
_active_run: ContextVar[tuple[str, int] | None] = ContextVar("secaudit_active_run", default=None)


def get_cancel_event() -> threading.Event | None:
    return _cancel_event.get()


def get_active_run() -> tuple[str, int] | None:
    return _active_run.get()


def is_cancelled() -> bool:
    event = _cancel_event.get()
    return bool(event and event.is_set())


def raise_if_cancelled(message: str = "Job run cancelled") -> None:
    if is_cancelled():
        raise InterruptedError(message)


@contextmanager
def cancel_scope(event: threading.Event | None = None) -> Iterator[threading.Event]:
    """Bind a cancel event for the current context (and child threads that copy context)."""
    token_event = event if event is not None else threading.Event()
    token = _cancel_event.set(token_event)
    try:
        yield token_event
    finally:
        _cancel_event.reset(token)


@contextmanager
def active_run_scope(run_kind: str, run_id: int) -> Iterator[tuple[str, int]]:
    """Bind the current JobRun/RemediationRun so ansible children can register PIDs."""
    ref = (run_kind, int(run_id))
    token = _active_run.set(ref)
    try:
        yield ref
    finally:
        _active_run.reset(token)
