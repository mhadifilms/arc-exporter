"""Safety guards — small functions that raise before we touch user data.

The principle is: every destructive operation must be preceded by a guard call. Tests
assert that each ``Target`` implementation references at least one guard from this
package before mutating data.
"""

from __future__ import annotations

from arc_exporter.guards.backups import BackupManager
from arc_exporter.guards.disk_space import ensure_disk_space
from arc_exporter.guards.running_browser import (
    BROWSER_PROCESS_NAMES,
    BrowserStatus,
    ensure_browsers_quit,
    running_browsers,
)

__all__ = [
    "BROWSER_PROCESS_NAMES",
    "BackupManager",
    "BrowserStatus",
    "ensure_browsers_quit",
    "ensure_disk_space",
    "running_browsers",
]
