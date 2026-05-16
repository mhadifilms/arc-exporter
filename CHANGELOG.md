# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - Unreleased

### Added
- Cross-platform Python package `arc_exporter` (macOS, Windows, Linux).
- `arc-exporter` CLI with `doctor`, `list`, `export`, `migrate`, `backup`, `rollback`,
  `targets` subcommands.
- Full Chromium-family migration: profile tree copy, native `Bookmarks` JSON
  synthesised from `StorableSidebar.json`, in-place cookie re-encryption against the
  destination's Safe Storage key, password and credit-card re-encryption.
- Direct extension migration via `Secure Preferences` HMAC resigning: the Arc
  extension folders ride along with the profile-tree copy, then
  `arc_exporter.targets.secure_prefs` walks `protection.macs` and rewrites every
  HMAC (plus `super_mac`) against the target browser's vendor seed and the
  current machine's device ID. The target browser trusts the resigned file on
  first launch and the user's extensions appear as already-installed — no Web
  Store round-trip, no install dialogs. Algorithm cross-validated against Arc's
  own MACs (29/29 + super_mac match) and Chrome's own MACs (7/7 + super_mac
  match) so we know it's byte-perfect with Chromium's `pref_hash_calculator.cc`.
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

## [0.1.0] - 2025-09

Initial macOS-only script release: single-file orchestration of Arc → Chrome profile
copy plus portable bookmarks / passwords / cards / extensions exports. Now replaced by
the `arc_exporter` package; the legacy entry point has been removed.
