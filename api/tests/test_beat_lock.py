from unittest.mock import MagicMock, patch

import pytest

from secaudit_core.beat_lock import acquire_beat_lock, release_beat_lock


def test_acquire_beat_lock_success():
    mock_client = MagicMock()
    mock_client.set.return_value = True

    with patch("secaudit_core.beat_lock.sync_redis", return_value=mock_client):
        client, token = acquire_beat_lock("redis://localhost:6379/0", "beat:schedule_lock:test")

    assert client is mock_client
    assert token is not None
    mock_client.set.assert_called_once()
    args, kwargs = mock_client.set.call_args
    assert args[0] == "beat:schedule_lock:test"
    assert args[1] == token
    assert kwargs["nx"] is True
    assert kwargs["ex"] == 55


def test_acquire_beat_lock_not_acquired():
    mock_client = MagicMock()
    mock_client.set.return_value = False

    with patch("secaudit_core.beat_lock.sync_redis", return_value=mock_client):
        client, token = acquire_beat_lock("redis://localhost:6379/0", "beat:schedule_lock:test")

    assert client is None
    assert token is None
    mock_client.close.assert_called_once()


def test_release_beat_lock_deletes_when_token_matches():
    mock_client = MagicMock()

    release_beat_lock(mock_client, "beat:schedule_lock:test", "token-123")

    mock_client.eval.assert_called_once()
    mock_client.close.assert_called_once()


def test_release_beat_lock_noop_when_not_acquired():
    release_beat_lock(None, "beat:schedule_lock:test", None)
