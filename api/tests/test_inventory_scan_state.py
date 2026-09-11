from unittest.mock import MagicMock, patch

from secaudit_core.inventory_scan_state import (
    is_scan_cancelled,
    request_scan_cancel,
    set_scan_pid,
)


def test_request_scan_cancel_sets_flag():
    mock_client = MagicMock()
    mock_client.get.return_value = None

    with patch("secaudit_core.inventory_scan_state._client", return_value=mock_client):
        request_scan_cancel("redis://localhost:6379/0", 7)

    mock_client.set.assert_called_once_with("inventory_scan:7:cancel", "1", ex=86400)


def test_is_scan_cancelled_reads_flag():
    mock_client = MagicMock()
    mock_client.get.return_value = "1"

    with patch("secaudit_core.inventory_scan_state._client", return_value=mock_client):
        assert is_scan_cancelled("redis://localhost:6379/0", 7) is True


def test_set_scan_pid_stores_pid():
    mock_client = MagicMock()

    with patch("secaudit_core.inventory_scan_state._client", return_value=mock_client):
        set_scan_pid("redis://localhost:6379/0", 3, 12345)

    mock_client.set.assert_called_once_with("inventory_scan:3:pid", "12345", ex=86400)
