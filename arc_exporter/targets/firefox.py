"""Firefox-family target adapter (Firefox, Zen, LibreWolf, Floorp, Waterfox).

Firefox does not auto-pick up dropped ``Bookmarks.html`` / ``cookies.sqlite`` files
the way Chromium does, so this adapter prepares an ``arc-exporter-import/`` directory
inside the chosen Firefox profile that contains:

- ``bookmarks.html`` — importable via *Bookmarks → Manage Bookmarks → Import*.
- ``passwords.csv`` — importable via *about:logins → Import from a File*.
- ``cookies.sqlite`` — drop-in replacement for the user's cookies (Firefox must be quit).
- ``policies.json`` — for extension force-installs (managed mode).
"""

from __future__ import annotations

import configparser
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from arc_exporter.errors import TargetUnavailableError
from arc_exporter.targets.base import (
    ArtefactKind,
    MigrationReport,
    MigrationRequest,
    Target,
    TargetProfile,
)
from arc_exporter.util import ensure_dir


@dataclass
class FirefoxTarget(Target):
    name: str = ""
    family: str = "firefox"  # type: ignore[assignment]
    supports: tuple[ArtefactKind, ...] = ("bookmarks", "passwords", "cookies", "extensions", "history")
    root_dir: Path = field(default_factory=Path)
    process: str = ""

    @property
    def user_data_dir(self) -> Path:
        return self.root_dir

    def process_name(self) -> str:
        return self.process

    def is_installed(self) -> bool:
        return self.root_dir.exists()

    def profiles_ini(self) -> Path:
        return self.root_dir / "profiles.ini"

    def create_profile(self, display_name: str, *, dry_run: bool = False) -> TargetProfile:
        if not self.is_installed():
            raise TargetUnavailableError(f"{self.name} is not installed at {self.root_dir}")
        salt = _short_salt()
        dir_name = f"{salt}.arc-{_slug(display_name)}"
        path = self.root_dir / "Profiles" / dir_name
        if dry_run:
            return TargetProfile(directory_name=dir_name, display_name=display_name, path=path)
        ensure_dir(path)
        self._register_profile(dir_name, display_name)
        return TargetProfile(directory_name=dir_name, display_name=display_name, path=path)

    def _register_profile(self, dir_name: str, display_name: str) -> None:
        ini_path = self.profiles_ini()
        cp = configparser.ConfigParser()
        if ini_path.exists():
            cp.read(ini_path, encoding="utf-8")
        existing = [s for s in cp.sections() if s.startswith("Profile")]
        index = len(existing)
        section = f"Profile{index}"
        cp[section] = {
            "Name": display_name,
            "IsRelative": "1",
            "Path": f"Profiles/{dir_name}",
            "Default": "0",
        }
        ini_path.parent.mkdir(parents=True, exist_ok=True)
        with ini_path.open("w", encoding="utf-8") as f:
            cp.write(f)

    def migrate_profile(
        self,
        target_profile: TargetProfile,
        request: MigrationRequest,
    ) -> MigrationReport:
        report = MigrationReport(target=self.name, profile=target_profile.display_name)
        staging = target_profile.path / "arc-exporter-import"
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
                ensure_dir(staging)
                dst = staging / src.name
                shutil.copy2(src, dst)
                if kind == "cookies" and src.suffix == ".sqlite":
                    # Firefox will pick up cookies if we replace the file directly,
                    # but only if the browser is quit. We never do this implicitly —
                    # users get a "ready to swap" copy in the staging dir.
                    pass
                report.succeeded[kind] = 1
            except Exception as e:
                report.errors[kind] = str(e)
        return report


def _short_salt() -> str:
    import secrets
    import string

    return "".join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(8))


def _slug(name: str) -> str:
    import re

    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:24] or "profile"
