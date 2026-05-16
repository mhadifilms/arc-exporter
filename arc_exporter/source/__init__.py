"""Reading Arc Browser data on the current OS.

Use :func:`get_source` to pick the right adapter automatically.
"""

from __future__ import annotations

import sys
from pathlib import Path

from arc_exporter.errors import ArcNotFoundError
from arc_exporter.source.base import ArcProfile, ArcSource

__all__ = ["ArcProfile", "ArcSource", "get_source"]


def get_source(override_root: Path | None = None) -> ArcSource:
    """Return the best :class:`ArcSource` for this OS.

    ``override_root`` lets tests (or unusual installs) point at an arbitrary directory.
    """
    if sys.platform == "darwin":
        from arc_exporter.source.arc_macos import ArcSourceMac

        return ArcSourceMac(override_root)
    if sys.platform == "win32":
        from arc_exporter.source.arc_windows import ArcSourceWindows

        return ArcSourceWindows(override_root)
    if sys.platform.startswith("linux"):
        # No native Arc on Linux yet, but tests run on Linux CI — return the mac adapter
        # pointed at an override directory if provided.
        from arc_exporter.source.arc_macos import ArcSourceMac

        if override_root is None:
            raise ArcNotFoundError("Arc is not available on Linux; use an override_root for testing")
        return ArcSourceMac(override_root)
    raise ArcNotFoundError(f"unsupported platform: {sys.platform}")
