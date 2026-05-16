"""Detect running browser processes before mutating their data.

Chromium-based browsers hold exclusive SQLite locks on ``Login Data``, ``Web Data``,
``Cookies``, and ``Local State`` while running. Writing while they're open silently
corrupts the databases — this guard refuses to proceed when a target is live.
"""

from __future__ import annotations

import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from arc_exporter.errors import BrowserRunningError

# Process executable names per OS, lowercased. Keep in sync with target adapters.
BROWSER_PROCESS_NAMES: Mapping[str, Mapping[str, tuple[str, ...]]] = {
    "darwin": {
        "arc": ("arc",),
        "chrome": ("google chrome", "google chrome helper"),
        "brave": ("brave browser", "brave browser helper"),
        "edge": ("microsoft edge", "microsoft edge helper"),
        "vivaldi": ("vivaldi", "vivaldi helper"),
        "opera": ("opera", "opera helper"),
        "dia": ("dia",),
        "safari": ("safari",),
        "firefox": ("firefox",),
        "zen": ("zen",),
        "librewolf": ("librewolf",),
        "floorp": ("floorp",),
        "waterfox": ("waterfox",),
        "orion": ("orion",),
    },
    "win32": {
        "arc": ("arc.exe",),
        "chrome": ("chrome.exe",),
        "brave": ("brave.exe",),
        "edge": ("msedge.exe",),
        "vivaldi": ("vivaldi.exe",),
        "opera": ("opera.exe", "opera_gx.exe"),
        "firefox": ("firefox.exe",),
        "zen": ("zen.exe",),
        "librewolf": ("librewolf.exe",),
        "floorp": ("floorp.exe",),
        "waterfox": ("waterfox.exe",),
    },
    "linux": {
        "chrome": ("chrome", "google-chrome", "google-chrome-stable"),
        "brave": ("brave", "brave-browser"),
        "edge": ("microsoft-edge", "msedge"),
        "vivaldi": ("vivaldi", "vivaldi-bin"),
        "opera": ("opera",),
        "firefox": ("firefox", "firefox-bin"),
        "zen": ("zen", "zen-bin"),
        "librewolf": ("librewolf",),
        "floorp": ("floorp",),
        "waterfox": ("waterfox",),
    },
}


@dataclass(frozen=True)
class BrowserStatus:
    name: str
    pids: tuple[int, ...]


def _names_for(platform_key: str) -> Mapping[str, tuple[str, ...]]:
    return BROWSER_PROCESS_NAMES.get(platform_key, {})


def _platform_key() -> str:
    if sys.platform.startswith("linux"):
        return "linux"
    return sys.platform


def running_browsers(browsers: Iterable[str] | None = None) -> list[BrowserStatus]:
    """Return one :class:`BrowserStatus` per browser that has live processes.

    ``browsers`` is a list of logical names (``"arc"``, ``"chrome"``, …). When ``None``
    we check every known browser for the current platform.

    Raises :class:`BrowserRunningError` only if ``psutil`` itself fails — *not* if a
    browser is running. Use :func:`ensure_browsers_quit` to enforce that.
    """
    try:
        import psutil
    except ImportError as e:
        raise BrowserRunningError("psutil is required to detect running browsers") from e

    targets = _names_for(_platform_key())
    if not targets:
        return []
    selected = {b: targets[b] for b in browsers if b in targets} if browsers else dict(targets)
    if not selected:
        return []

    matches: dict[str, list[int]] = {b: [] for b in selected}
    for proc in psutil.process_iter(attrs=["pid", "name"]):
        try:
            pname = (proc.info.get("name") or "").lower()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        if not pname:
            continue
        for b, names in selected.items():
            for n in names:
                if pname == n or pname.startswith(n + "."):
                    matches[b].append(proc.info["pid"])
                    break
    return [BrowserStatus(b, tuple(pids)) for b, pids in matches.items() if pids]


_GRACEFUL_NAMES: Mapping[str, str] = {
    "arc": "Arc",
    "chrome": "Google Chrome",
    "brave": "Brave Browser",
    "edge": "Microsoft Edge",
    "vivaldi": "Vivaldi",
    "opera": "Opera",
    "dia": "Dia",
    "safari": "Safari",
    "firefox": "Firefox",
    "zen": "Zen",
    "librewolf": "LibreWolf",
    "floorp": "Floorp",
    "waterfox": "Waterfox",
    "orion": "Orion",
}


def auto_quit_browsers(browsers: Iterable[str], *, timeout: float = 8.0) -> list[BrowserStatus]:
    """Ask each running browser to quit gracefully, then wait briefly.

    Returns the list of browsers still running after the grace period. Callers should
    feed that back into :func:`ensure_browsers_quit` to decide whether to proceed.

    Implementation notes:

    - macOS: uses ``osascript`` to send the standard ``quit`` AppleEvent. This lets
      Chrome write its session state cleanly so the user's pinned tabs and last-open
      tabs survive.
    - Windows: tries ``taskkill /F /IM <exe>``. There is no clean-shutdown equivalent
      that AppleScript provides, so for Windows we recommend the user quit manually
      and only fall back to ``taskkill`` here.
    - Linux: sends SIGTERM to each pid then waits.
    """
    import subprocess
    import time

    matches = running_browsers(browsers)
    if not matches:
        return matches

    if sys.platform == "darwin":
        for b in matches:
            display = _GRACEFUL_NAMES.get(b.name, b.name.title())
            subprocess.run(
                ["/usr/bin/osascript", "-e", f'tell application "{display}" to quit'],
                capture_output=True,
                check=False,
            )
    elif sys.platform == "win32":
        names = _names_for("win32")
        for b in matches:
            for exe in names.get(b.name, ()):
                subprocess.run(["taskkill", "/F", "/IM", exe], capture_output=True, check=False)
    else:
        try:
            import os
            import signal

            for b in matches:
                for pid in b.pids:
                    try:
                        os.kill(pid, signal.SIGTERM)
                    except (OSError, ProcessLookupError):
                        pass
        except ImportError:
            pass

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        remaining = running_browsers(browsers)
        if not remaining:
            return []
        time.sleep(0.5)
    return running_browsers(browsers)


def ensure_browsers_quit(
    browsers: Iterable[str],
    *,
    force: bool = False,
    auto_quit: bool = False,
) -> list[BrowserStatus]:
    """Raise :class:`BrowserRunningError` if any listed browser has live processes.

    Returns the (possibly empty) list of detected processes. When ``force=True`` it
    returns them but does *not* raise — letting the caller log the override. When
    ``auto_quit=True`` we first try to gracefully terminate them (see
    :func:`auto_quit_browsers`) and only raise if any survive the grace period.
    """
    matches = running_browsers(browsers)
    if matches and auto_quit:
        matches = auto_quit_browsers(browsers)
    if not matches:
        return matches
    if force:
        return matches
    names = ", ".join(b.name for b in matches)
    pid_summary = "; ".join(f"{b.name} pids={list(b.pids)}" for b in matches)
    raise BrowserRunningError(
        f"the following browser(s) are running and may lock their data files: {names}. "
        f"Quit them (Cmd+Q on macOS, taskkill on Windows), pass --auto-quit to terminate "
        f"them gracefully, or pass --force to override at your own risk. Detail: {pid_summary}."
    )
