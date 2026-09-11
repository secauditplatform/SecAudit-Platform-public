"""P2 host-parallel cancellation and remote path isolation tests."""

from __future__ import annotations

import threading
import time

import pytest

from app.cancel_context import get_cancel_event, is_cancelled
from app.executors.ssh import unique_remote_script_path
from app.host_parallel import run_hosts_parallel


def test_run_hosts_parallel_stops_submitting_after_cancel():
    started: list[int] = []
    started_lock = threading.Lock()
    cancel_after = threading.Event()

    def worker(item: int) -> int:
        with started_lock:
            started.append(item)
        if item == 0:
            cancel_after.set()
            time.sleep(0.35)
        else:
            time.sleep(0.05)
        if is_cancelled():
            raise InterruptedError("cancelled")
        return item

    def should_cancel() -> bool:
        return cancel_after.is_set() and len(started) >= 1

    with pytest.raises(InterruptedError):
        run_hosts_parallel(
            list(range(20)),
            concurrency=2,
            worker_fn=worker,
            should_cancel=should_cancel,
        )

    # Bounded submission: must not have launched every host.
    assert len(started) < 20
    assert len(started) <= 6


def test_run_hosts_parallel_sets_cancel_event_for_workers():
    held_events: list = []
    gate = threading.Event()

    def worker(_item: int) -> int:
        event = get_cancel_event()
        assert event is not None
        held_events.append(event)
        gate.wait(timeout=2)
        if event.is_set() or is_cancelled():
            raise InterruptedError("cancelled")
        return 0

    cancel = threading.Event()

    def should_cancel() -> bool:
        return cancel.is_set()

    def run():
        with pytest.raises(InterruptedError):
            run_hosts_parallel([1, 2, 3], 2, worker, should_cancel=should_cancel)

    thread = threading.Thread(target=run)
    thread.start()
    # Wait until workers have bound the cancel event, then cancel.
    deadline = time.time() + 2
    while time.time() < deadline and len(held_events) < 1:
        time.sleep(0.02)
    assert held_events, "worker did not observe cancel event"
    cancel.set()
    # Unblock workers so they can observe the set flag.
    gate.set()
    thread.join(timeout=3)
    assert not thread.is_alive()
    assert held_events[0].is_set()


def test_unique_remote_script_paths_are_isolated():
    paths = {unique_remote_script_path("check_passwd", ".sh") for _ in range(50)}
    assert len(paths) == 50
    for path in paths:
        assert path.startswith("/tmp/secaudit_check_passwd_")
        assert path.endswith(".sh")
    # Must not collapse to the legacy stem-only path.
    assert "/tmp/secaudit_check_passwd.sh" not in paths


def test_python_suffix_paths_also_unique():
    paths = {unique_remote_script_path("audit", ".py") for _ in range(20)}
    assert len(paths) == 20
    assert all(p.endswith(".py") for p in paths)
