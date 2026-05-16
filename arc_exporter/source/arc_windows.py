"""Arc Browser on Windows (beta).

Arc on Windows installs as a Microsoft Store / AppX package; data lives under
``%LocalAppData%\\Packages\\TheBrowserCompany.Arc_*\\LocalCache\\Local\\Arc``. The exact
package family name has changed across the beta but always starts with
``TheBrowserCompany.Arc``.
"""

from __future__ import annotations

import os
from pathlib import Path

from arc_exporter.errors import ArcNotFoundError
from arc_exporter.source.base import ArcProfile, ArcSource, ArcSourceConfig


class ArcSourceWindows(ArcSource):
    PACKAGE_PREFIX = "TheBrowserCompany.Arc"

    def __init__(self, override_root: Path | None = None) -> None:
        root = override_root or self._auto_detect_root()
        self._config = ArcSourceConfig(
            user_data_dir=root / "User Data",
            local_state_path=root / "User Data" / "Local State",
            sidebar_path=root / "StorableSidebar.json",
            # Chrome on Windows derives keys differently (DPAPI-wrapped AES-GCM); arc-exporter
            # does not yet read those keys from the Windows Credential Store.
            safe_storage_services=(),
        )

    def _auto_detect_root(self) -> Path:
        local = os.environ.get("LOCALAPPDATA")
        if not local:
            raise ArcNotFoundError("LOCALAPPDATA not set; cannot locate Arc on Windows")
        packages = Path(local) / "Packages"
        if not packages.is_dir():
            raise ArcNotFoundError(f"no AppX packages directory at {packages}")
        candidates = sorted(p for p in packages.iterdir() if p.name.startswith(self.PACKAGE_PREFIX))
        if not candidates:
            raise ArcNotFoundError(
                f"no {self.PACKAGE_PREFIX} package under {packages}; Arc may not be installed"
            )
        return candidates[0] / "LocalCache" / "Local" / "Arc"

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
            if not entry.is_dir() or entry.name in system or not (entry / "Preferences").exists():
                continue
            out.append(
                ArcProfile(
                    directory_name=entry.name,
                    display_name=display.get(entry.name, entry.name),
                    path=entry,
                )
            )
        return out
