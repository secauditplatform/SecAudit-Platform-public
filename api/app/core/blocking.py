"""Bounded execution for unavoidable synchronous API operations."""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from typing import Any, Callable, TypeVar

from app.core.config import settings

T = TypeVar("T")
_MAX_WORKERS = max(1, settings.blocking_io_max_workers)
_executor = ThreadPoolExecutor(max_workers=_MAX_WORKERS, thread_name_prefix="secaudit-io")
_slots = asyncio.Semaphore(_MAX_WORKERS)


async def run_blocking(
    function: Callable[..., T],
    /,
    *args: Any,
    timeout: float | None = None,
    **kwargs: Any,
) -> T:
    """Run synchronous I/O without using the unbounded default executor queue."""
    await _slots.acquire()
    loop = asyncio.get_running_loop()
    future = loop.run_in_executor(_executor, partial(function, *args, **kwargs))
    released = False

    def release_slot(_future=None) -> None:
        nonlocal released
        if not released:
            released = True
            _slots.release()

    try:
        if timeout is None:
            result = await asyncio.shield(future)
        else:
            result = await asyncio.wait_for(asyncio.shield(future), timeout=timeout)
    except (asyncio.CancelledError, TimeoutError):
        future.add_done_callback(release_slot)
        raise
    except Exception:
        release_slot()
        raise
    release_slot()
    return result
