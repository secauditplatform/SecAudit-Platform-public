"""Run ansible-runner in a child process with a sanitized environment.

The worker process holds platform secrets (SECRET_KEY, database/Redis
credentials). ansible-runner seeds its environment from ``os.environ``, so a
playbook could read those values with controller-side templating. This module
is started with an allowlisted environment and returns only runner results.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import ansible_runner


def _read_stdout(stream: object) -> str:
    if stream is None:
        return ""
    if hasattr(stream, "read"):
        value = stream.read()  # type: ignore[union-attr]
        return str(value or "").strip()
    return str(stream).strip()


def main() -> int:
    payload = json.load(sys.stdin)
    run_kwargs = dict(payload["run_kwargs"])
    cancel_path = Path(payload["cancel_path"])
    result_path = Path(payload["result_path"])
    run_kwargs["cancel_callback"] = lambda: cancel_path.exists()

    result: dict = {
        "status": None,
        "rc": None,
        "stats": {},
        "events": [],
        "stdout": "",
        "error": None,
    }
    try:
        runner = ansible_runner.run(**run_kwargs)
        result.update(
            {
                "status": runner.status,
                "rc": runner.rc,
                "stats": runner.stats or {},
                "events": list(runner.events),
                "stdout": _read_stdout(runner.stdout),
            }
        )
    except Exception as exc:  # noqa: BLE001 - the parent reports the failure
        result["error"] = f"{type(exc).__name__}: {exc}"

    result_path.write_text(json.dumps(result, default=str), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
