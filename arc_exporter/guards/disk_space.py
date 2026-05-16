"""Disk-space precondition check.

Arc profiles can be 1–10 GB each. We refuse to start a profile copy unless the
destination has at least 1.5× the source size free, otherwise we leave the user with a
half-copied Chrome profile and no easy recovery.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from arc_exporter.errors import ArcExporterError


class DiskSpaceError(ArcExporterError):
    exit_code = 10


def directory_size(path: Path) -> int:
    """Recursive byte size; skips dangling symlinks and unreadable files quietly."""
    total = 0
    for root, _, files in os.walk(path, followlinks=False):
        for name in files:
            try:
                total += os.path.getsize(os.path.join(root, name))
            except OSError:
                continue
    return total


def ensure_disk_space(target_dir: Path, *, required_bytes: int, headroom: float = 1.5) -> int:
    """Raise :class:`DiskSpaceError` if ``target_dir`` has less than ``required * headroom`` free.

    Returns the number of free bytes for callers that want to log it.
    """
    target_dir.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(target_dir).free
    need = int(required_bytes * headroom)
    if free < need:
        raise DiskSpaceError(
            f"insufficient disk space at {target_dir}: have {free:,} bytes, need {need:,} "
            f"(source is {required_bytes:,} bytes, {headroom:.1f}× headroom)"
        )
    return free
