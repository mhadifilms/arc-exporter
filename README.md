# arc-exporter

> Safely migrate Arc Browser profiles into Chrome, Brave, Edge, Vivaldi, Opera, Dia,
> Firefox, Zen, LibreWolf, Floorp, Waterfox, Safari, and Orion — without losing
> bookmarks, passwords, cards, cookies, extensions, history, or open tabs.

[![CI](https://github.com/mhadifilms/arc-exporter/actions/workflows/ci.yml/badge.svg)](https://github.com/mhadifilms/arc-exporter/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## What it does

Reads your Arc data on your machine, decrypts what it needs to in memory only, and
produces both portable artefacts (NETSCAPE bookmarks HTML, password CSV, Firefox
`cookies.sqlite`, extensions report, history JSON, …) and direct migrations into the
browser of your choice. Nothing is sent over the network.

For Chromium-family targets (Chrome, Brave, Edge, Vivaldi, Opera, Dia) the migration
copies the entire Arc profile tree into a new target profile, re-encrypts saved
passwords / credit cards / cookies against the destination browser's Safe Storage
key, and synthesizes a native `Bookmarks` JSON from Arc's `StorableSidebar.json` so
your pinned tabs appear in the bookmark bar.

For Firefox-family targets and Safari/Orion, the tool drops import-ready files into
`Profile N/imports/` inside the target's user-data directory so you can load them
through the target's built-in importer.

## Install

```bash
# Recommended: isolated pipx install
pipx install arc-exporter

# From source
git clone https://github.com/mhadifilms/arc-exporter
cd arc-exporter
pip install -e .
```

A Homebrew formula and standalone binaries are planned; see the Releases page once
they ship.

## Quick start

```bash
# 1. Quit Arc and the target browser, OR pass --auto-quit to have us do it.
# 2. Sanity-check your environment.
arc-exporter doctor

# 3. List your Arc profiles so you can confirm what will be migrated.
arc-exporter list

# 4. Migrate every Arc profile into the target browser of your choice.
arc-exporter migrate --to=chrome
# also: brave, edge, vivaldi, opera, dia, firefox, zen, librewolf, floorp,
# waterfox, safari, orion

# 5. Or, if you just want portable export files (no target browser changes):
arc-exporter export all
```

The default output directory is OS-appropriate (`~/Library/Application
Support/arc-exporter/exports/runs/<timestamp>/` on macOS). Override with `--output`.

Every command supports:

- `--dry-run` — plan only, no writes
- `-v` / `-vv` — info / debug logging
- `--force` — bypass the running-browser guard at your own risk
- `--auto-quit` — try to gracefully quit running browsers before proceeding
- `--keep-cache-dirs` — also copy `Cache` / `Code Cache` / `GPUCache` (skipped by default)
- `--strip-storage` — drop `IndexedDB` / `Local Storage` / `Session Storage` /
  `File System` (signs you out of most web apps; not recommended)

## Undoing a migration

Every target profile created by arc-exporter is marked with a small
`.arc-exporter.json` file. The `rollback` command uses that marker to find and
remove them without ever touching profiles you created yourself.

```bash
arc-exporter rollback ls --to=chrome
arc-exporter rollback rm --to=chrome --profile "Profile 3"
arc-exporter rollback rm --to=chrome --all -y
```

## What gets migrated

| Kind        | Portable artefact                       | Chromium direct migration                     | Firefox direct migration              |
|-------------|-----------------------------------------|-----------------------------------------------|---------------------------------------|
| Bookmarks   | NETSCAPE `bookmarks.html`               | Synthesizes a native `Bookmarks` JSON         | `bookmarks.html` placed in `imports/` |
| Passwords   | `passwords.csv` (chmod 600)             | Re-encrypted into target `Login Data`         | CSV placed in `imports/`              |
| Cards       | Reference CSV (last 4 digits only)      | Re-encrypted into target `Web Data`           | —                                     |
| Cookies     | Firefox `cookies.sqlite` + JSON         | Re-encrypted in-place in target `Cookies`     | `cookies.sqlite` placed in `imports/` |
| Extensions  | HTML report with Chrome Web Store links | Per-profile report placed in `imports/`       | `policies.json` for force-install     |
| History     | JSON + HTML                             | Copied as-is (plaintext)                      | —                                     |
| Open tabs   | OneTab / Toby-compatible JSON           | —                                             | —                                     |
| Easels/Notes| Markdown (best-effort scrape)           | —                                             | —                                     |

## Security defaults

- Passwords, cards, and cookies are decrypted **in memory only** — the legacy
  approach of shelling out to `openssl` (which briefly leaked plaintext to `/tmp`)
  is gone.
- Every file containing credentials gets `chmod 0600` from the moment of creation.
- Bookmark titles, URLs, extension names, and any other user-controlled string is
  HTML-escaped before being emitted, so a malicious page title cannot inject script
  into the exported HTML.
- The tool refuses to mutate target-browser data while that browser is running.
  Pass `--auto-quit` to terminate them gracefully or `--force` to override.
- Every modification to a target browser's databases is backed up first under
  `~/Library/Application Support/Google/Chrome/.arc-exporter-backups/` (or
  equivalent), restorable via `arc-exporter backup restore <id>`.
- macOS Keychain access is cached per process so you grant permission at most once
  per Safe Storage entry per run.
- The Chrome→AMO extension mapping fetch is capped at 50 pages so a misbehaving
  endpoint cannot loop indefinitely.

See [SECURITY.md](SECURITY.md) for the full threat model and how to report a
vulnerability.

## Contributing

Issues and PRs welcome. Please don't open public issues for security
vulnerabilities; use the private channel in [SECURITY.md](SECURITY.md).

## Licence

MIT. See [LICENSE](LICENSE).
