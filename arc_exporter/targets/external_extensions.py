"""Two-phase Chrome bootstrap: extensions install, then user-facing relaunch.

Phase 1 (extension install, briefly visible Chrome):

  1. Stage ``<id>.json`` descriptors in the target's ``External Extensions/``
     directory. Each descriptor points at the Chrome Web Store update URL
     ``clients2.google.com/service/update2/crx``. On launch Chrome silently
     pulls fresh CRX bundles from the Web Store — Google-signed, so they
     pass Chromium's content-verification subsystem cleanly. (Arc's on-disk
     ``Extensions/<id>/`` binaries fail that check because Arc patches
     several extensions; copying them produces ``DISABLE_CORRUPTED``.)
  2. Launch the target browser briefly with ``--profile-directory=<Profile N>``.
     A ``rich`` progress bar polls ``Extensions/`` for each new directory.
  3. SIGTERM Chrome once everything is installed (or quiesce-fires). The
     graceful shutdown is what lets us safely modify ``Secure Preferences``
     between phases — Chrome holds the file open while running, and the
     auto-enable step (caller's responsibility) needs to write into it.

Between phases, the caller does the cross-profile fixups: auto-enable the
freshly installed extensions, set ``session.restore_on_startup = 1``, etc.

Phase 2 (tabs visible, Chrome stays running):

  1. Re-launch Chrome with ``--profile-directory=<Profile N>`` plus every
     URL we want open as a positional argument. Chrome opens them as
     ordinary tabs in load order. Pinned-tab pinning and tab groups are
     intentionally *not* attempted: Chrome 142+ removed every escape hatch
     short of publishing a Web Store extension (``--load-extension``,
     ``Extensions.loadUnpacked`` CDP method, and local-CRX install on
     macOS are all blocked). Right-click → Pin tab is the user-facing
     workaround surfaced in the CLI Next Steps panel.
  2. Wait briefly for tabs to settle, then close any leftover starter tabs
     (``about:blank`` / NTP) via the DevTools HTTP endpoints so the user
     doesn't see an empty placeholder.
  3. Detach: do NOT terminate the process. The user wanted Chrome to stay
     open with their tabs and extensions ready to use.
"""

from __future__ import annotations

import json
import logging
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from pathlib import Path

from rich.console import Console
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

log = logging.getLogger(__name__)

_WEB_STORE_UPDATE_URL = "https://clients2.google.com/service/update2/crx"
_DESCRIPTOR_BODY = {"external_update_url": _WEB_STORE_UPDATE_URL}

# How often we poll Extensions/ and the DevTools target list. The quiesce
# guard fires once nothing's made progress for this many seconds — usually
# means Chrome finished or one extension was delisted from the Web Store.
_POLL_INTERVAL_S = 1.5
_QUIESCE_S = 12.0

# Titles / URLs we treat as "placeholder starter tabs" and close at the end
# of phase 2 so the user opens the window into something useful.
_STARTER_URLS = ("chrome://newtab/", "about:blank")


def install_extensions_for_profile(
    *,
    extension_ids: list[str],
    target_profile_path: Path,
    browser_binary: Path | None,
    external_extensions_dir: Path,
    timeout_s: float = 240.0,
    profile_display_name: str | None = None,
    console: Console | None = None,
) -> tuple[list[str], list[str]]:
    """Phase 1: Install Web Store extensions into the target profile, then quit.

    Returns ``(installed, not_installed)``. ``installed`` extensions have a
    folder under ``target_profile_path/Extensions/<id>/``; ``not_installed``
    are the IDs Chrome refused or that have been delisted from the Web Store.

    Chrome is launched briefly with ``--profile-directory`` and SIGTERMed
    once everything is installed (or the quiesce timer fires). The
    descriptor files are removed afterwards so they don't leak into other
    profiles on subsequent Chrome launches.
    """
    wanted = sorted({eid for eid in extension_ids if _looks_like_extension_id(eid)})
    if not wanted:
        return [], []
    if browser_binary is None or not browser_binary.exists():
        log.warning("browser binary %r not found; cannot install extensions", browser_binary)
        return [], list(wanted)

    if console is None:
        console = Console(stderr=True)
    label = profile_display_name or target_profile_path.name

    console.print(
        f"[dim]Installing extensions for [bold]{label}[/] "
        f"({len(wanted)} from the Chrome Web Store)…[/]"
    )

    external_extensions_dir.mkdir(parents=True, exist_ok=True)
    created: list[Path] = []
    proc: subprocess.Popen[bytes] | None = None
    installed: set[str] = set()
    try:
        for ext_id in wanted:
            desc_path = external_extensions_dir / f"{ext_id}.json"
            desc_path.write_text(json.dumps(_DESCRIPTOR_BODY), encoding="utf-8")
            created.append(desc_path)

        cmd = [
            str(browser_binary),
            f"--profile-directory={target_profile_path.name}",
            "--no-first-run",
            "--no-default-browser-check",
            "--disable-features=ChromeWhatsNewUI",
            "about:blank",
        ]
        log.info(
            "phase 1 launch: %s for profile %s (%d extensions)",
            browser_binary.name,
            label,
            len(wanted),
        )
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        ext_root = target_profile_path / "Extensions"
        installed = _poll_extensions_done(
            ext_root=ext_root,
            wanted=wanted,
            timeout_s=timeout_s,
            console=console,
            label=label,
        )
    finally:
        _shutdown(proc)
        # IMPORTANT: leave the descriptor files in place permanently.
        #
        # Chrome's external-extensions garbage collector auto-uninstalls
        # every ``location=6 (EXTERNAL_PREF_DOWNLOAD)`` entry whose
        # descriptor is missing on a subsequent launch — diagnosed
        # empirically against Chrome 148: deleting the descriptors here
        # caused 23/23 extensions to vanish (Secure Preferences entries
        # wiped, ``Extensions/<id>/`` folders garbage collected) on the
        # next Chrome start.
        #
        # We previously tried promoting ``location`` from 6 → 1 (INTERNAL)
        # and re-signing the prefs to dodge this cleanup, but Chrome 148
        # re-demotes the entry to 6 on next launch when it sees no
        # corresponding install_signature claim, and the wipe still
        # happens because external-extensions cleanup runs against the
        # demoted entry. The only durable solution is to keep the
        # descriptor as Chrome's source-of-truth that says "this
        # extension is meant to be here."
        #
        # The descriptors are tiny ({"external_update_url": "…"} per
        # extension, ~75 bytes each), idempotent (re-running migration
        # rewrites them), and Chrome's own External Extensions mechanism
        # — they're not a hack, they're the supported (if deprecated)
        # API for bootstrapping Web Store extensions.

    not_installed = [eid for eid in wanted if eid not in installed]
    if not_installed:
        console.print(
            f"[yellow]  {len(not_installed)} extension(s) didn't auto-install "
            "(probably removed from the Web Store). See the HTML report for "
            "direct links.[/]"
        )
    elif installed:
        console.print(f"[green]  all {len(installed)} extension(s) installed for {label}[/]")
    return sorted(installed), not_installed


def launch_chrome_with_tabs(
    *,
    target_profile_path: Path,
    browser_binary: Path,
    urls: Iterable[str],
    profile_display_name: str | None = None,
    console: Console | None = None,
    settle_seconds: float = 6.0,
) -> int:
    """Phase 2: Re-launch Chrome for the user, open their tabs, leave running.

    Returns the number of tabs the user will see (URLs we passed minus any
    starter tabs we successfully closed). Chrome is NOT terminated.

    On macOS we go through ``/usr/bin/open -na`` instead of ``Popen`` on the
    inner binary, because launching the inner binary directly has bitten us
    twice now (terminal crash on a previous run, plus weird stdio coupling
    that Chrome's helper processes inherit). ``open`` hands the launch off
    to LaunchServices and returns immediately — no Popen handle to manage,
    no shared file descriptors, no SIGHUP propagation from the parent
    terminal. We still drive cleanup of starter tabs through Chrome's
    DevTools HTTP endpoint, which doesn't need a PID — only the port.

    Pin / tab-group state can't be reproduced programmatically — Chrome 142+
    removed every external API for it. We open everything as ordinary tabs
    in the order ``urls`` provides; the caller is expected to put pinned
    URLs first so they at least end up leftmost in the tab strip.
    """
    if console is None:
        console = Console(stderr=True)
    label = profile_display_name or target_profile_path.name
    url_list = [u for u in urls if u]

    if not url_list:
        log.info("[phase 2] no tabs to open for %s; skipping relaunch", label)
        return 0

    debug_port = _free_port()
    console.print(
        f"[dim]Opening [bold]{label}[/] in Chrome with "
        f"{len(url_list)} tab(s) (Chrome stays open)…[/]"
    )

    chrome_args = [
        f"--profile-directory={target_profile_path.name}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-features=ChromeWhatsNewUI",
        f"--remote-debugging-port={debug_port}",
        "--remote-allow-origins=*",
        *url_list,
    ]
    log.info(
        "phase 2 launch: %s for profile %s (%d tabs, port=%d)",
        browser_binary.name,
        label,
        len(url_list),
        debug_port,
    )

    if sys.platform == "darwin":
        # ``open -n`` forces a NEW Chrome process even when Chrome is
        # already running (so we know our --profile-directory arg actually
        # creates the window we want). ``-a`` selects the app bundle by
        # path/name so we don't have to hardcode the inner binary path.
        # ``--args`` passes everything that follows to Chrome.
        #
        # We pass the absolute ``.app`` bundle path rather than just the
        # bundle name. macOS's ``open`` resolves a bare name via
        # LaunchServices, which is fine for "Google Chrome" but fails
        # silently (``Unable to find application named 'Contents'``,
        # exit code 1) if we miscompute the basename. Earlier code
        # walked the wrong number of ``parents`` and ended up trying to
        # launch ``"Contents"``; using the full bundle path makes the
        # invocation immune to that off-by-one and surfaces the actual
        # bundle on the rare error.
        bundle_path = _macos_app_bundle(browser_binary)
        launcher = [
            "/usr/bin/open",
            "-na",
            str(bundle_path) if bundle_path else browser_binary.parts[-3],
            "--args",
            *chrome_args,
        ]
        r = subprocess.run(
            launcher,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            check=False,
        )
        if r.returncode != 0:
            log.warning(
                "open returned %d when launching %s: %s",
                r.returncode,
                bundle_path or browser_binary,
                (r.stderr or b"").decode("utf-8", "replace").strip()[:200],
            )
    else:
        # Other platforms: ``start_new_session=True`` puts Chrome in its
        # own process group so SIGHUP to the arc-exporter terminal
        # doesn't propagate. DEVNULL on stdio keeps Chrome from blocking
        # on dying log pipes after we exit.
        subprocess.Popen(
            [str(browser_binary), *chrome_args],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )

    # Give Chrome a moment to come up and open the URL args, then close any
    # starter tabs (NTP / about:blank) that Chrome inserted alongside ours.
    # The polling here is best-effort: we never want to wedge the migration
    # waiting on Chrome.
    deadline = time.monotonic() + settle_seconds
    closed = 0
    saw_real_tab = False
    while time.monotonic() < deadline:
        tabs = _devtools_list_tabs(debug_port)
        # Distinguish a "real" tab (something we navigated to) from a
        # starter tab. Only close starters once at least one real tab is
        # already showing — otherwise we'd race Chrome to close NTP
        # before it loaded the URL args.
        real = [t for t in tabs if not _is_starter_tab(t.get("url") or "")]
        if real:
            saw_real_tab = True
        if saw_real_tab:
            for t in tabs:
                url = t.get("url") or ""
                if _is_starter_tab(url) and len(tabs) > 1:
                    _devtools_close_tab(debug_port, t.get("id", ""))
                    closed += 1
            break
        time.sleep(0.5)
    if closed:
        log.info("[phase 2] closed %d starter tab(s) on %s", closed, label)
    return max(0, len(url_list))


def _is_starter_tab(url: str) -> bool:
    return any(url.startswith(s) for s in _STARTER_URLS)


def _poll_extensions_done(
    *,
    ext_root: Path,
    wanted: list[str],
    timeout_s: float,
    console: Console,
    label: str,
    sleep: Callable[[float], None] = time.sleep,
) -> set[str]:
    """Block on a rich progress bar until every wanted extension exists on
    disk or the quiesce timer fires (== Chrome stopped making progress)."""
    deadline = time.monotonic() + timeout_s
    installed: set[str] = set()
    last_progress = time.monotonic()
    progress_cols = (
        SpinnerColumn(),
        TextColumn(f"[cyan]Installing for {label}[/cyan]"),
        BarColumn(),
        TextColumn("[bold]{task.completed}/{task.total}[/bold]"),
        TimeElapsedColumn(),
    )
    with Progress(*progress_cols, console=console, transient=False) as progress:
        task = progress.add_task("install", total=len(wanted))
        while time.monotonic() < deadline:
            now_installed = _installed_ids(ext_root, wanted)
            if len(now_installed) > len(installed):
                last_progress = time.monotonic()
            installed = now_installed
            progress.update(task, completed=len(installed))
            if installed == set(wanted):
                break
            if installed and time.monotonic() - last_progress > _QUIESCE_S:
                # Chrome stalled: usually one or two extensions were delisted
                # from the Web Store. Call it; the caller surfaces a note.
                break
            sleep(_POLL_INTERVAL_S)
        installed = _installed_ids(ext_root, wanted)
        progress.update(task, completed=len(installed))
    return installed


def macos_app_binary(process_name: str) -> Path | None:
    """Return the macOS executable path for a Chromium app, or ``None``."""
    if sys.platform != "darwin":
        return None
    candidate = Path("/Applications") / f"{process_name}.app" / "Contents/MacOS" / process_name
    if candidate.exists():
        return candidate
    return None


def _macos_app_bundle(binary: Path) -> Path | None:
    """Walk up from ``binary`` to find the enclosing ``*.app`` directory.

    Chromium-family inner binaries live at
    ``…/<Name>.app/Contents/MacOS/<Name>``, so the bundle is two levels
    above the inner binary. We don't hardcode that depth, though — we
    walk the parent chain until we hit something ending in ``.app``.
    This makes the helper resilient to weird app structures and to
    refactors that change where the binary lives.

    Returns ``None`` if no ``.app`` ancestor exists; the caller falls
    back to a sensible default (the legacy basename guess).
    """
    for parent in binary.parents:
        if parent.suffix == ".app":
            return parent
    return None


def _installed_ids(ext_root: Path, wanted: list[str]) -> set[str]:
    if not ext_root.exists():
        return set()
    wanted_set = set(wanted)
    return {
        p.name
        for p in ext_root.iterdir()
        if p.is_dir() and p.name in wanted_set and any(p.iterdir())
    }


def _looks_like_extension_id(value: str) -> bool:
    return isinstance(value, str) and len(value) == 32 and value.isalpha() and value.islower()


def _free_port() -> int:
    """Return a free localhost TCP port. Same trick stdlib unittest uses."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _devtools_list_tabs(port: int) -> list[dict]:
    """Return the tabs list from Chrome's DevTools HTTP endpoint, or [] on failure.

    Falls back silently when Chrome hasn't fully bound the port yet — the
    caller is in a polling loop and will retry shortly.
    """
    try:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/json/list", timeout=1.5
        ) as resp:
            data = json.loads(resp.read())
    except (urllib.error.URLError, OSError, json.JSONDecodeError):
        return []
    return [t for t in data if t.get("type") == "page"]


def _devtools_close_tab(port: int, target_id: str) -> None:
    """Close a single DevTools target (== close a tab). Errors are swallowed
    because we'd rather miss a starter tab than fail the whole migration."""
    if not target_id:
        return
    try:
        with urllib.request.urlopen(
            f"http://127.0.0.1:{port}/json/close/{target_id}", timeout=2.0
        ) as _resp:
            pass
    except (urllib.error.URLError, OSError):
        pass


def _shutdown(proc: subprocess.Popen[bytes] | None) -> None:
    """Graceful Chrome shutdown — used between phase 1 and phase 2.

    SIGTERM gives Chrome's SessionService time to write out its in-memory
    state (Secure Preferences with the freshly-installed extensions). A
    plain SIGKILL would strand the install half-registered, which is
    exactly the failure mode that previously left profiles with zero
    enabled extensions.
    """
    if proc is None:
        return
    try:
        proc.terminate()
    except OSError:
        pass
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except OSError:
            pass
