"""Pluggable browser targets.

Each target is a small dataclass + adapter pair so adding a new browser is a single
file. The registry below is what the CLI uses to enumerate ``--to=...`` choices.
"""

from __future__ import annotations

from arc_exporter.targets.base import (
    MigrationReport,
    MigrationRequest,
    Target,
    TargetProfile,
)
from arc_exporter.targets.registry import all_targets, available_targets, target_by_name

__all__ = [
    "MigrationReport",
    "MigrationRequest",
    "Target",
    "TargetProfile",
    "all_targets",
    "available_targets",
    "target_by_name",
]
