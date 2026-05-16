"""Safari (macOS) target.

Safari does not maintain explicit "profiles" the way Chromium does (until macOS 14,
which added a partial profile system). Our integration is intentionally minimal:

- Bookmarks: write a NETSCAPE HTML to ``~/Library/Safari/arc-exporter/bookmarks.html``
  and instruct the user to import via *File → Import From → Bookmarks HTML File*.
- Passwords: write Apple-format CSV to ``~/Library/Safari/arc-exporter/passwords.csv``
  for *Preferences → Passwords → File → Import Passwords*.

Safari requires Full Disk Access for the calling process to read its bookmarks plist;
:mod:`arc_exporter.doctor` checks that and prints a clear remediation.
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
class SafariTarget(Target):
    name: str = "safari"
    family: str = "safari"  # type: ignore[assignment]
    supports: tuple[ArtefactKind, ...] = ("bookmarks", "passwords")

    SAFARI_DIR = Path.home() / "Library/Safari"

    @property
    def user_data_dir(self) -> Path:
        return self.SAFARI_DIR

    def process_name(self) -> str:
        return "Safari"

    def is_installed(self) -> bool:
        return self.SAFARI_DIR.exists()

    def create_profile(self, display_name: str, *, dry_run: bool = False) -> TargetProfile:
        path = self.SAFARI_DIR / "arc-exporter" / display_name
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
