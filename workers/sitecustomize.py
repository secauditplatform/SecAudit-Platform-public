"""Harden Python worker processes against /proc/<pid>/environ reads.

Ansible templating can reach Python builtins and read another process's
environment. PR_SET_DUMPABLE=0 makes /proc/<pid>/environ unreadable to
same-UID processes, including the ansible-runner child.
"""

from __future__ import annotations

import ctypes

try:
    ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE
except Exception:  # pragma: no cover - non-Linux or restricted seccomp
    pass
