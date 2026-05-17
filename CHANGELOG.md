# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-05-16

### Added
- Cross-platform Python package `arc_exporter` (macOS, Windows, Linux).
- `arc-exporter` CLI with `doctor`, `list`, `export`, `migrate`, `backup`, `rollback`,
  `targets` subcommands.
- Full Chromium-family migration: profile tree copy, native `Bookmarks` JSON
  synthesised from `StorableSidebar.json`, in-place cookie re-encryption against the
  destination's Safe Storage key, password and credit-card re-encryption.
- Arc-faithful bookmark / tab split for Chromium targets. Arc keeps three
  distinct URL buckets per space and we now map each to the right Chrome
  surface:
  - **Favorites** (Arc's icon strip) -> Chrome bookmark bar, flat. Only
    these end up as Chrome *bookmarks* — previous releases dumped pinned
    tabs in there too and the bookmark bar got unusable fast.
  - **Pinned tabs** -> open Chrome tabs, leftmost in the tab strip.
  - **Today tabs** -> open Chrome tabs, after the pinned ones.
  `session.restore_on_startup` is forced to 1 ("Continue where you left
  off") in the migrated `Preferences` between the two launches below, so
  on every subsequent Chrome launch the tabs come back instead of being
  silently discarded.
  > Note: Chrome 142+ removed every external API (`--load-extension`,
  > CDP `Extensions.loadUnpacked`, local-CRX install on macOS) that
  > third-party tools used to call `chrome.tabs.update({pinned:true})` /
  > `chrome.tabGroups`. Pin / group state can no longer be set
  > programmatically without publishing a Web Store extension; pinned
  > URLs come back as the leftmost ordinary tabs and the user
  > right-clicks → "Pin tab" if they want them pinned.
- Two-phase Chrome bootstrap (`arc_exporter.targets.external_extensions`).
  Per profile we launch Chrome twice, with all between-phase work
  happening while Chrome is OFF (so our `Secure Preferences` edits aren't
  clobbered by Chrome rewriting the file on shutdown):
  1. **Phase 1 — extension install.** Brief Chrome launch with
     `External Extensions/<id>.json` descriptors pointing at
     `clients2.google.com/service/update2/crx`. Arc's on-disk
     `Extensions/<id>/<ver>/` binaries are never copied — Arc patches
     several extensions, so they fail Chromium's
     `verified_contents.json` content verification and end up
     `DISABLE_CORRUPTED`. Google-signed CRX bundles from the Web Store
     pass cleanly. A `rich` progress bar polls `Extensions/` for each
     install; Chrome is SIGTERMed once everything is in place.
  2. **Between phases.** Three edits are made while Chrome is OFF, in a
     single resign pass so the HMACs end up consistent:
     - `state=1` is set + `disable_reasons` cleared on freshly-installed
       extensions. On Chrome 142+ this is reset back to
       `DISABLE_EXTERNAL_EXTENSION` on next launch (Chrome's
       unavoidable side-load consent gate), so users still see a
       one-click "Enable" prompt per extension — the CLI Next Steps
       panel calls this out. Older Chromium forks honour the clear.
     - `location` is flipped from `6` (EXTERNAL_PREF_DOWNLOAD) to `1`
       (INTERNAL). Chrome 142+ demotes it back to `6` when it sees the
       matching descriptor on launch; we still do it for older forks.
     - `session.restore_on_startup = 1` is written into `Preferences`.
     Both `Secure Preferences` and `Preferences` are resigned against
     the target's HMAC seed via `arc_exporter.targets.secure_prefs`.
     The resign now covers the Chrome 137+ `*_encrypted_hash` entries
     (OSCrypt-encrypted SHA256 alongside the legacy HMAC) in addition
     to the legacy MACs and `super_mac` — without those, any value we
     touch gets silently wiped on the next Chrome launch even though
     the HMAC is correct. The algorithm is a mechanical port of
     `PrefHashCalculator::CalculateEncryptedHash` +
     `OSCryptImpl::EncryptString`, verified bit-for-bit against
     Chrome's own stored output (test
     `test_calculate_encrypted_matches_chromium_algorithm`).
     External Extensions descriptors are kept on disk permanently
     after phase 1. Deleting them used to trigger Chrome's
     external-extensions garbage collector to wipe every entry on the
     next launch ("0 extensions installed"); they're tiny
     (~75 bytes/extension) and idempotent, and removing them silently
     produces the regression every time.
  3. **Phase 2 — tabs.** Chrome is relaunched with `--profile-directory`
     plus the pinned + today URLs as positional arguments. Chrome opens
     them as ordinary tabs in load order. The DevTools HTTP endpoints
     are then used to close any leftover starter tab (NTP /
     `about:blank`). Chrome is left running for the user. On macOS the
     relaunch goes through `/usr/bin/open -na "Google Chrome" --args …`
     (LaunchServices) instead of `subprocess.Popen` on the inner
     binary; this is what fixes the "terminal crashed" report — the
     direct-binary launch coupled the Chrome process tree to the
     parent terminal's tty in a way that, combined with Python's
     `Popen` ResourceWarning chatter on exit, was wedging the shell.
     Other platforms still use `subprocess.Popen` with
     `start_new_session=True` for the same effect.
  Before phase 1 we also strip Arc's stale `extensions.settings` /
  `protection.macs.extensions.settings` entries out of the copied
  `Preferences` / `Secure Preferences` and resign against the target
  browser's vendor seed (Python port of Chromium's
  `pref_hash_calculator.cc`, cross-validated against Arc's own MACs
  29/29 + super_mac and Chrome's own MACs 7/7 + super_mac).
- Web-Store-only extension filter: only entries with `from_webstore=true`
  AND a `clients2.google.com` update URL are passed to the External
  Extensions installer. Drops Chrome built-ins Arc keeps in its prefs
  ("Web Store", "Chromium PDF Viewer", "Google Hangouts", "Arc Internal
  Extension") that previously showed up as bogus "didn't auto-install"
  warnings every run.
- `--auto-quit` flag that gracefully terminates running browsers (osascript on
  macOS, taskkill on Windows, SIGTERM on Linux) before the running-browser guard.
- `rollback` subcommand to safely remove profiles created by arc-exporter, keyed on
  a per-profile `.arc-exporter.json` marker so we never touch user-created profiles.
- Process-level caching of keychain lookups so each Safe Storage entry is queried at
  most once per run.
- Pluggable browser targets: Chromium family (Chrome, Brave, Edge, Vivaldi, Opera, Dia,
  Arc Search, Sidekick, Comet), Firefox family (Firefox, Zen, LibreWolf, Floorp, Waterfox),
  Safari (macOS), Orion (macOS).
- In-memory AES-128-CBC Chromium v10 crypto via `cryptography` (no temp-file leaks).
- Chromium v20 (Windows App-Bound Encryption) decoding scaffold.
- `psutil`-based running-browser guard with `--force` override.
- `rich`-powered progress and end-of-run summary table.
- `--dry-run`, `--verbose`, `--keep-cache-dirs` flags.
- Cycle-safe sidebar bookmark parser.
- AMO mapping pagination cap.
- HTML-escaped bookmark / extension HTML output with `ADD_DATE` and favicon support.
- History (HTML/JSON), open-tabs (JSON for OneTab/Toby), easels/notes (Markdown), reading
  list exporters.
- Versioned, restorable backups for any file we touch in target browsers.
- Per-file `chmod 0o600` for `passwords_*.csv`, `cards_*.csv`, `cookies_*.sqlite`.
- MIT `LICENSE`, `CONTRIBUTING.md`, GitHub issue/PR templates, `SECURITY.md`.
- pytest test suite with anonymised SQLite + sidebar fixtures.
- GitHub Actions CI matrix (`{macos-13, macos-14, ubuntu-latest, windows-latest} × {3.10, 3.11, 3.12}`).
- Release workflow producing PyPI wheel, Homebrew bottle, `.pkg`, `.msi`, `.deb`/`.rpm`, `.AppImage`.

### Changed
- Output layout: `arc-export/runs/<timestamp>/` instead of overwriting `arc-export/` each run.
- Replaced `print` + global `VERBOSE` with `rich` + `logging`.
- Replaced `security` + `openssl` subprocess shellouts with in-process `keyring` + `cryptography`.

### Removed
- Always-on `ChromeProfileMonitor` background thread.
- Unconditional `shutil.rmtree(OUT_ROOT)` on every run.
- Plaintext-on-disk decrypted password / PAN temp files.

### Fixed
- `register_chrome_profile` / `copy_profile_safely` collision bug that registered the wrong
  Chrome profile directory after rename.
- Cross-profile contamination from `External Extensions` descriptors.
- Loss of signed-in web-app sessions caused by stripping `IndexedDB` / `Local Storage`
  during profile copy (now opt-in via `--strip-storage`).
- Phase 2's macOS relaunch was running `/usr/bin/open -na "Contents" --args …`
  because the bundle name walked one too few `Path.parents`; `open` exited 1
  with "Unable to find application named 'Contents'" but `check=False` hid
  it, so Chrome never started and the user saw "Chrome stays open"
  followed by no Chrome. The bundle is now resolved by walking up until
  a `.app` ancestor is found and the full bundle path is passed to
  `open`; non-zero exit codes from `open` are logged.
- Arc's `Sessions/` directory plus the root-level `Current Session` /
  `Current Tabs` / `Last Session` / `Last Tabs` files were riding along
  with the profile-tree copy. Chrome's session restore then reopened
  every URL Arc had loaded at quit time (often 50+ tabs of random
  browsing) on phase 1's near-silent extension-install launch, drowning
  out the curated pinned + today-tabs we wanted in phase 2. `Sessions/`
  is now in the copy skip set and the root-level files are removed
  post-copy by `_clean_session_artifacts`.

## [0.1.0] - 2025-09

Initial macOS-only script release: single-file orchestration of Arc → Chrome profile
copy plus portable bookmarks / passwords / cards / extensions exports. Now replaced by
the `arc_exporter` package; the legacy entry point has been removed.
