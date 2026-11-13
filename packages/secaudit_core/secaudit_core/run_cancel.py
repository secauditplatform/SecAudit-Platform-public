"""Redis-backed JobRun / RemediationRun cancel flags and child PIDs.

API sets the cancel flag (cross-container). The worker owns the PIDs and must
kill them — Docker PID namespaces make os.kill from the API a silent no-op.
"""

from __future__ import annotations

import os
import signal

from secaudit_core.redis_client import sync_redis

_CANCEL_TTL_SECONDS = 86400


def _cancel_key(run_kind: str, run_id: int) -> str:
    return f"{run_kind}_run:{int(run_id)}:cancel"


def _pids_key(run_kind: str, run_id: int) -> str:
    return f"{run_kind}_run:{int(run_id)}:pids"


def set_run_cancel_flag(redis_url: str, run_kind: str, run_id: int) -> None:
    """Signal cancel; workers poll this and kill local ansible/SSH children."""
    client = sync_redis(redis_url, decode_responses=True)
    try:
        client.set(_cancel_key(run_kind, run_id), "1", ex=_CANCEL_TTL_SECONDS)
    finally:
        client.close()


def kill_run_child_pids(redis_url: str, run_kind: str, run_id: int) -> None:
    """SIGKILL process groups registered by this worker for the run."""
    client = sync_redis(redis_url, decode_responses=True)
    try:
        pids = client.smembers(_pids_key(run_kind, run_id)) or set()
        for raw in pids:
            try:
                pid = int(raw)
            except (TypeError, ValueError):
                continue
            try:
                os.killpg(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                try:
                    os.kill(pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    pass
    finally:
        client.close()


def request_run_cancel(redis_url: str, run_kind: str, run_id: int) -> None:
    """Set cancel flag and best-effort kill (only works in the worker PID ns)."""
    set_run_cancel_flag(redis_url, run_kind, run_id)
    kill_run_child_pids(redis_url, run_kind, run_id)


def is_run_cancel_requested(redis_url: str, run_kind: str, run_id: int) -> bool:
    client = sync_redis(redis_url, decode_responses=True)
    try:
        return client.get(_cancel_key(run_kind, run_id)) == "1"
    finally:
        client.close()


def register_run_child_pid(redis_url: str, run_kind: str, run_id: int, pid: int) -> None:
    client = sync_redis(redis_url, decode_responses=True)
    try:
        key = _pids_key(run_kind, run_id)
        client.sadd(key, str(int(pid)))
        client.expire(key, _CANCEL_TTL_SECONDS)
    finally:
        client.close()


def unregister_run_child_pid(redis_url: str, run_kind: str, run_id: int, pid: int) -> None:
    client = sync_redis(redis_url, decode_responses=True)
    try:
        client.srem(_pids_key(run_kind, run_id), str(int(pid)))
    finally:
        client.close()


def clear_run_cancel_state(redis_url: str, run_kind: str, run_id: int) -> None:
    client = sync_redis(redis_url, decode_responses=True)
    try:
        client.delete(_cancel_key(run_kind, run_id), _pids_key(run_kind, run_id))
    finally:
        client.close()
