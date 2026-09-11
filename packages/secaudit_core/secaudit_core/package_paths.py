"""Safe path resolution for profile package scripts."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

SHELL_SCRIPT_SUFFIXES = frozenset({".sh", ".bash"})
PACKAGE_COPY_IGNORE = shutil.ignore_patterns(
    "__pycache__",
    "*.pyc",
    "*.pyo",
    ".git",
    ".DS_Store",
)


def resolve_script_under_package(package_dir: Path, script_file: str) -> Path:
    """Resolve script_file to an absolute path confined to package_dir."""
    if not script_file or not str(script_file).strip():
        raise ValueError("script_file is empty")

    normalized = script_file.replace("\\", "/").lstrip("/")
    if ".." in Path(normalized).parts:
        raise ValueError(f"script_file must stay inside package: {script_file!r}")

    package_root = package_dir.resolve()
    if not package_root.is_dir():
        raise FileNotFoundError(f"Package directory not found: {package_dir}")

    resolved = (package_root / normalized).resolve()
    if package_root not in resolved.parents and resolved != package_root:
        raise ValueError(f"script_file escapes package directory: {script_file!r}")

    if not resolved.is_file():
        raise FileNotFoundError(f"Script not found in package: {script_file!r}")

    return resolved


def normalize_text_newlines(text: str) -> str:
    """Normalize Windows/Mac newlines to Unix LF."""
    return text.replace("\r\n", "\n").replace("\r", "\n")


def normalize_shell_script_bytes(data: bytes) -> bytes:
    """Normalize CRLF/CR to LF for shell scripts executed on Linux hosts."""
    if b"\r" not in data:
        return data
    return data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")


def normalize_shell_script_file(path: Path) -> bool:
    """Convert CRLF/CR to LF in place for shell scripts. Returns True if changed."""
    if path.suffix.lower() not in SHELL_SCRIPT_SUFFIXES or not path.is_file():
        return False
    raw = path.read_bytes()
    normalized = normalize_shell_script_bytes(raw)
    if normalized == raw:
        return False
    path.write_bytes(normalized)
    return True


def normalize_shell_scripts_in_tree(root: Path) -> int:
    """Normalize all shell scripts under root. Returns number of files changed."""
    if not root.is_dir():
        return 0
    changed = 0
    for path in root.rglob("*"):
        if path.is_file() and normalize_shell_script_file(path):
            changed += 1
    return changed


def _rmtree_best_effort(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path, ignore_errors=True)


def remove_package_tree(path: Path) -> None:
    """Remove a stored package dir even if worker-owned ``__pycache__`` remains."""
    if not path.exists():
        return
    stale = path.with_name(f".{path.name}.stale-{os.getpid()}")
    try:
        if stale.exists():
            _rmtree_best_effort(stale)
        path.rename(stale)
    except OSError:
        _rmtree_best_effort(path)
        return
    _rmtree_best_effort(stale)


def replace_package_tree(source: Path, dest: Path) -> Path:
    """Copy ``source`` onto ``dest``, ignoring interpreter caches.

    Prefers a sibling temp dir + rename. When the parent volume is not writable
    for the current user (common with reused Docker named volumes) but ``dest``
    already exists and is writable, stages the copy inside ``dest`` instead.
    """
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass

    sibling_tmp = dest.with_name(f".{dest.name}.tmp-{os.getpid()}")
    try:
        _rmtree_best_effort(sibling_tmp)
        shutil.copytree(source, sibling_tmp, ignore=PACKAGE_COPY_IGNORE)
        if dest.exists():
            remove_package_tree(dest)
        sibling_tmp.rename(dest)
        return dest
    except PermissionError:
        _rmtree_best_effort(sibling_tmp)
        if not dest.exists():
            raise
        return _replace_package_tree_inplace(source, dest)
    except Exception:
        _rmtree_best_effort(sibling_tmp)
        raise


def _replace_package_tree_inplace(source: Path, dest: Path) -> Path:
    """Replace package contents when only ``dest`` (not its parent) is writable."""
    incoming = dest / f".sync-tmp-{os.getpid()}"
    _rmtree_best_effort(incoming)
    try:
        shutil.copytree(source, incoming, ignore=PACKAGE_COPY_IGNORE)
        for child in list(dest.iterdir()):
            if child.name == incoming.name:
                continue
            if child.is_dir():
                _rmtree_best_effort(child)
            else:
                try:
                    child.unlink()
                except OSError:
                    pass
        for child in list(incoming.iterdir()):
            target = dest / child.name
            if target.exists():
                if target.is_dir():
                    _rmtree_best_effort(target)
                else:
                    target.unlink(missing_ok=True)
            child.rename(target)
        _rmtree_best_effort(incoming)
    except Exception:
        _rmtree_best_effort(incoming)
        raise
    return dest
