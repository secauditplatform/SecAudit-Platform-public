"""Host-level parallelism within a single Celery task."""

from __future__ import annotations

import contextvars
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from typing import TypeVar

from app.cancel_context import cancel_scope, get_cancel_event

T = TypeVar("T")
R = TypeVar("R")


def _submit_with_context(executor: ThreadPoolExecutor, fn: Callable[[T], R], item: T):
    """Preserve ContextVars (cancel token) in worker threads."""
    ctx = contextvars.copy_context()
    return executor.submit(ctx.run, fn, item)


def run_hosts_parallel(
    items: list[T],
    concurrency: int,
    worker_fn: Callable[[T], R],
    *,
    should_cancel: Callable[[], bool] | None = None,
) -> list[R]:
    """Run worker_fn per item with bounded thread parallelism.

    Cancellation:
    - Stops submitting new hosts once cancelled.
    - Signals a shared cancel event so executors can abort in-flight work.
    - Uses ``cancel_futures`` / does not wait forever on cancelled work.
    """
    if not items:
        return []

    max_workers = max(1, min(concurrency, len(items)))

    with cancel_scope(get_cancel_event()) as cancel_event:

        def _cancelled() -> bool:
            if cancel_event.is_set():
                return True
            if should_cancel and should_cancel():
                cancel_event.set()
                return True
            return False

        if max_workers == 1:
            results: list[R] = []
            for item in items:
                if _cancelled():
                    raise InterruptedError("Job run cancelled")
                results.append(worker_fn(item))
            return results

        results_map: dict[int, R] = {}
        next_index = 0
        in_flight: dict = {}

        # Do not wait on the executor context exit for cancelled futures.
        executor = ThreadPoolExecutor(max_workers=max_workers)
        try:
            while next_index < len(items) or in_flight:
                if _cancelled():
                    for future in list(in_flight):
                        future.cancel()
                    cancel_event.set()
                    raise InterruptedError("Job run cancelled")

                while next_index < len(items) and len(in_flight) < max_workers:
                    if _cancelled():
                        cancel_event.set()
                        raise InterruptedError("Job run cancelled")
                    item = items[next_index]
                    future = _submit_with_context(executor, worker_fn, item)
                    in_flight[future] = next_index
                    next_index += 1

                if not in_flight:
                    break

                done, _ = wait(in_flight.keys(), return_when=FIRST_COMPLETED, timeout=0.5)
                if not done:
                    # Periodic cancel poll while hosts are still running.
                    continue

                for future in done:
                    index = in_flight.pop(future)
                    if _cancelled():
                        for pending in list(in_flight):
                            pending.cancel()
                        cancel_event.set()
                        raise InterruptedError("Job run cancelled")
                    results_map[index] = future.result()
        finally:
            # Python 3.9+: cancel_futures drops queued work; running threads
            # rely on the cancel event / executor abort paths.
            executor.shutdown(wait=False, cancel_futures=True)

        if _cancelled():
            raise InterruptedError("Job run cancelled")

        return [results_map[i] for i in range(len(items))]
