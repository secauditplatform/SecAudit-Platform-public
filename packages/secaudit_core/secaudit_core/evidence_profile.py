"""Profile identity captured when a compliance run starts.

The evidence pack reads this snapshot. It must not be replaced later with the
profile as it looks on disk today.
"""

from __future__ import annotations

from pathlib import Path

from secaudit_core.profile_packages import package_encoding_hint


def profile_snapshot_from_profile(profile) -> dict:
    encoding = None
    package_path = getattr(profile, "package_path", None)
    if package_path:
        try:
            encoding = package_encoding_hint(Path(package_path))
        except OSError:
            encoding = None
    version = getattr(profile, "version", None)
    return {
        "profile_id": profile.id,
        "profile_name": profile.profile_name,
        "version": str(version) if version else None,
        "encoding": encoding,
    }
