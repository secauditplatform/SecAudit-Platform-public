"""Cooperative cancellation token shared across host-parallel workers."""

from __future__ import annotations

import threading
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Iterator

_cancel_event: ContextVar[threading.Event | None] = ContextVar("secaudit_cancel_event", default=None)


def get_cancel_event() -> threading.Event | None:
    return _cancel_event.get()


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
