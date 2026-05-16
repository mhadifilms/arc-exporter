"""Arc Browser on macOS."""

from __future__ import annotations

from pathlib import Path

from arc_exporter.errors import ArcNotFoundError
from arc_exporter.source.base import ArcProfile, ArcSource, ArcSourceConfig


class ArcSourceMac(ArcSource):
    """``~/Library/Application Support/Arc`` layout."""

    DEFAULT_ROOT = Path.home() / "Library/Application Support/Arc"

    def __init__(self, override_root: Path | None = None) -> None:
        root = override_root or self.DEFAULT_ROOT
        self._config = ArcSourceConfig(
            user_data_dir=root / "User Data",
            local_state_path=root / "User Data" / "Local State",
            sidebar_path=root / "StorableSidebar.json",
            safe_storage_services=("Arc Safe Storage", "Chrome Safe Storage", "Chromium Safe Storage"),
        )

    @property
    def config(self) -> ArcSourceConfig:
        return self._config

    def is_installed(self) -> bool:
        return self._config.user_data_dir.is_dir()

    def profiles(self) -> list[ArcProfile]:
        if not self.is_installed():
            raise ArcNotFoundError(f"Arc not found at {self._config.user_data_dir}")
        system = self.system_profile_dirs()
        display = self.display_names()
        out: list[ArcProfile] = []
        for entry in sorted(self._config.user_data_dir.iterdir(), key=lambda p: p.name):
            if not entry.is_dir():
                continue
            if entry.name in system:
                continue
            if not (entry / "Preferences").exists():
                continue
            out.append(
                ArcProfile(
                    directory_name=entry.name,
                    display_name=display.get(entry.name, entry.name),
                    path=entry,
                )
            )
        return out
