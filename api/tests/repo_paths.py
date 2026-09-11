"""Resolve monorepo paths in host checkouts and Docker API containers."""

from __future__ import annotations

import os
from pathlib import Path


def _api_tests_dir() -> Path:
    return Path(__file__).resolve().parent


def monorepo_root() -> Path | None:
    """Host checkout root. None in API-only containers."""
    api_dir = _api_tests_dir().parent
    root = api_dir.parent
    if (root / "api").is_dir() and (root / "scripts").is_dir():
        return root
    return None


def secaudit_core_root() -> Path:
    docker_mount = Path("/packages/secaudit_core")
    if docker_mount.is_dir():
        return docker_mount
    root = monorepo_root()
    if root is not None:
        return root / "packages" / "secaudit_core"
    raise FileNotFoundError("secaudit_core package not found (mount /packages/secaudit_core)")


def profiles_root() -> Path:
    env = os.environ.get("PROFILES_PATH", "").strip()
    if env:
        path = Path(env)
        if path.is_dir():
            return path
    docker_mount = Path("/profiles")
    if docker_mount.is_dir():
        return docker_mount
    root = monorepo_root()
    if root is not None:
        return root / "profiles"
    raise FileNotFoundError("profiles catalog not found (mount /profiles or set PROFILES_PATH)")


def scripts_root() -> Path:
    docker_mount = Path("/scripts")
    if docker_mount.is_dir():
        return docker_mount
    root = monorepo_root()
    if root is not None:
        return root / "scripts"
    raise FileNotFoundError("scripts directory not found (mount /scripts or run from monorepo)")
