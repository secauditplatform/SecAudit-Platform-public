"""Transient exception classification for Celery autoretry."""

from __future__ import annotations

import errno

import pytest
from sqlalchemy.exc import OperationalError

from secaudit_core.celery_reliability import TransientOSError
from secaudit_core.transient import is_transient_error, reraise_if_transient


def test_connection_error_is_transient():
    assert is_transient_error(ConnectionError("db down"))
    assert is_transient_error(TimeoutError("timed out"))
    assert is_transient_error(OperationalError("stmt", {}, Exception("x")))


def test_transient_oserror_errno_is_transient():
    assert is_transient_error(OSError(errno.ECONNRESET, "connection reset"))
    assert is_transient_error(OSError(errno.ETIMEDOUT, "timed out"))


def test_local_oserror_is_not_transient():
    assert not is_transient_error(OSError(errno.ENOENT, "no such file"))
    assert not is_transient_error(OSError(errno.EACCES, "permission denied"))
    assert not is_transient_error(OSError(errno.ENOSPC, "no space"))


def test_business_errors_are_not_transient():
    assert not is_transient_error(ValueError("bad host"))
    assert not is_transient_error(RuntimeError("script failed"))
    assert not is_transient_error(InterruptedError("cancelled"))


def test_reraise_if_transient_propagates_connection_error():
    with pytest.raises(ConnectionError):
        try:
            raise ConnectionError("boom")
        except Exception as exc:
            reraise_if_transient(exc)
            raise AssertionError("should have re-raised") from exc


def test_reraise_if_transient_wraps_network_oserror():
    with pytest.raises(TransientOSError):
        try:
            raise OSError(errno.ENETUNREACH, "network unreachable")
        except Exception as exc:
            reraise_if_transient(exc)
            raise AssertionError("should have re-raised") from exc


def test_reraise_if_transient_swallows_permanent_oserror():
    try:
        raise OSError(errno.ENOENT, "missing")
    except Exception as exc:
        reraise_if_transient(exc)
        assert exc.errno == errno.ENOENT


def test_reraise_if_transient_swallows_permanent_runtime():
    try:
        raise RuntimeError("permanent")
    except Exception as exc:
        reraise_if_transient(exc)
        assert str(exc) == "permanent"
