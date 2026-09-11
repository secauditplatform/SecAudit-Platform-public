import threading
import time
from unittest.mock import patch

from app.tasks.compliance import _run_with_progress_logs


@patch("app.tasks.compliance.publish_job_log")
def test_run_with_progress_logs_emits_heartbeat(mock_publish):
    started = threading.Event()

    def execute() -> str:
        started.set()
        time.sleep(0.05)
        return "ok"

    assert _run_with_progress_logs(146, "Ubuntu23(XC)", "Docker_scripts.sh", execute, interval_seconds=0) == "ok"
    started.wait(timeout=1)
    mock_publish.assert_called()


@patch("app.tasks.compliance.publish_job_log")
def test_run_with_progress_logs_propagates_errors(mock_publish):
    def execute() -> str:
        raise RuntimeError("boom")

    try:
        _run_with_progress_logs(146, "Ubuntu23(XC)", "Docker_scripts.sh", execute, interval_seconds=0)
    except RuntimeError as exc:
        assert str(exc) == "boom"
    else:
        raise AssertionError("expected RuntimeError")
