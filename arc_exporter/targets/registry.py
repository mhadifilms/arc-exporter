"""Concrete target registry. Adding a new browser = one entry here + one adapter."""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

from arc_exporter.errors import TargetUnavailableError
from arc_exporter.targets.base import Target


def _chromium(name: str, dir_name: str, services: tuple[str, ...], process: str) -> Callable[[], Target]:
    from arc_exporter.targets.chromium import ChromiumTarget

    def factory() -> Target:
        return ChromiumTarget(
            name=name, root_dir=_chromium_root(dir_name), services=services, process=process
        )

    return factory


def _firefox(name: str, dir_name: str, process: str) -> Callable[[], Target]:
    from arc_exporter.targets.firefox import FirefoxTarget

    def factory() -> Target:
        return FirefoxTarget(name=name, root_dir=_firefox_root(dir_name), process=process)

    return factory


def _chromium_root(dir_name: str) -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library/Application Support" / dir_name
    if sys.platform == "win32":
        import os

        local = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData/Local")
        return Path(local) / dir_name / "User Data"
    return Path.home() / ".config" / dir_name


def _firefox_root(dir_name: str) -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library/Application Support" / dir_name
    if sys.platform == "win32":
        import os

        roaming = os.environ.get("APPDATA") or str(Path.home() / "AppData/Roaming")
        return Path(roaming) / dir_name
    return Path.home() / ".mozilla" / dir_name


_FACTORIES: dict[str, Callable[[], Target]] = {
    # Chromium family — name (CLI key) -> (root dir name, Safe Storage services, process name)
    "chrome": _chromium(
        "chrome", "Google/Chrome", ("Chrome Safe Storage", "Chromium Safe Storage"), "Google Chrome"
    ),
    "brave": _chromium(
        "brave", "BraveSoftware/Brave-Browser", ("Brave Safe Storage", "Chrome Safe Storage"), "Brave Browser"
    ),
    "edge": _chromium(
        "edge", "Microsoft Edge", ("Microsoft Edge Safe Storage", "Chromium Safe Storage"), "Microsoft Edge"
    ),
    "vivaldi": _chromium("vivaldi", "Vivaldi", ("Vivaldi Safe Storage", "Chromium Safe Storage"), "Vivaldi"),
    "opera": _chromium(
        "opera", "com.operasoftware.Opera", ("Opera Safe Storage", "Chromium Safe Storage"), "Opera"
    ),
    "dia": _chromium("dia", "Dia", ("Dia Safe Storage", "Chromium Safe Storage"), "Dia"),
    "arc-search": _chromium(
        "arc-search", "Arc Search", ("Arc Search Safe Storage", "Chromium Safe Storage"), "Arc Search"
    ),
    "sidekick": _chromium(
        "sidekick", "Sidekick", ("Sidekick Safe Storage", "Chromium Safe Storage"), "Sidekick"
    ),
    "comet": _chromium("comet", "Comet", ("Comet Safe Storage", "Chromium Safe Storage"), "Comet"),
    # Firefox family
    "firefox": _firefox("firefox", "Firefox", "Firefox"),
    "zen": _firefox("zen", "zen", "Zen"),
    "librewolf": _firefox("librewolf", "LibreWolf", "LibreWolf"),
    "floorp": _firefox("floorp", "Floorp", "Floorp"),
    "waterfox": _firefox("waterfox", "Waterfox", "Waterfox"),
}


def _add_macos_only_targets() -> None:
    if sys.platform != "darwin":
        return
    from arc_exporter.targets.orion import OrionTarget
    from arc_exporter.targets.safari import SafariTarget

    _FACTORIES["safari"] = SafariTarget
    _FACTORIES["orion"] = OrionTarget


_add_macos_only_targets()


def all_targets() -> dict[str, Target]:
    """Return one instance of every known target, regardless of whether it's installed."""
    return {k: factory() for k, factory in _FACTORIES.items()}


def available_targets() -> dict[str, Target]:
    """Return only the targets whose user-data dir or app is present on this machine."""
    return {k: t for k, t in all_targets().items() if t.is_installed()}


def target_by_name(name: str) -> Target:
    name = name.lower().replace("_", "-")
    factory = _FACTORIES.get(name)
    if factory is None:
        raise TargetUnavailableError(f"unknown target {name!r}. Known: {sorted(_FACTORIES)}")
    return factory()
