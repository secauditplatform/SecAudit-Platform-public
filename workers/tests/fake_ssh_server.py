"""Fake SSH server for worker connectivity tests."""

from __future__ import annotations

import socket
import threading


class FakeSshServer:
    """Minimal TCP server that accepts one connection and returns an SSH banner."""

    def __init__(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self) -> None:
        conn, _addr = self._sock.accept()
        with conn:
            conn.sendall(b"SSH-2.0-FakeSecAudit\r\n")
            conn.recv(1024)

    def close(self) -> None:
        self._sock.close()
