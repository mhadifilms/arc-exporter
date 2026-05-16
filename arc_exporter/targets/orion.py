"""Kagi Orion (macOS) target.

Orion is a WebKit-based browser that accepts Chrome's NETSCAPE bookmarks HTML through
its standard import dialog and Chromium-style CSV password files. Our adapter mirrors
:class:`SafariTarget` — drop the import-ready files in a known location and let the
user click through Orion's import UI.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from arc_exporter.targets.base import (
    ArtefactKind,
    MigrationReport,
    MigrationRequest,
    Target,
    TargetProfile,
)
from arc_exporter.util import ensure_dir


@dataclass
class OrionTarget(Target):
    name: str = "orion"
    family: str = "orion"  # type: ignore[assignment]
    supports: tuple[ArtefactKind, ...] = ("bookmarks", "passwords")

    ORION_DIR = Path.home() / "Library/Application Support/Orion"

    @property
    def user_data_dir(self) -> Path:
        return self.ORION_DIR

    def process_name(self) -> str:
        return "Orion"

    def is_installed(self) -> bool:
        return self.ORION_DIR.exists()

    def create_profile(self, display_name: str, *, dry_run: bool = False) -> TargetProfile:
        path = self.ORION_DIR / "arc-exporter" / display_name
        if not dry_run:
            ensure_dir(path)
        return TargetProfile(directory_name=path.name, display_name=display_name, path=path)

    def migrate_profile(
        self,
        target_profile: TargetProfile,
        request: MigrationRequest,
    ) -> MigrationReport:
        report = MigrationReport(target=self.name, profile=target_profile.display_name)
        for kind, src in request.artefact_paths.items():
            if kind not in self.supports:
                report.skipped[kind] = "not supported by this target"
                continue
            if not src.exists():
                report.skipped[kind] = f"file missing: {src}"
                continue
            try:
                if request.dry_run:
                    report.succeeded[kind] = 0
                    continue
                ensure_dir(target_profile.path)
                shutil.copy2(src, target_profile.path / src.name)
                report.succeeded[kind] = 1
            except Exception as e:
                report.errors[kind] = str(e)
        return report
