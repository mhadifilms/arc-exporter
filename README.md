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

For Chromium-family targets (Chrome, Brave, Edge, Vivaldi, Opera, Dia) the
migration copies the entire Arc profile tree into a new target profile,
re-encrypts saved passwords / credit cards / cookies against the destination
browser's Safe Storage key, and faithfully reproduces Arc's three URL buckets:

- **Favorites** (Arc's icon strip across the top of each space) become Chrome
  bookmarks in the bookmark bar.
- **Pinned tabs** become open Chrome tabs at the left of the tab strip.
  Chrome 142+ removed the only external APIs third-party tools used to pin
  tabs or create tab groups (`--load-extension` is silently ignored,
  `Extensions.loadUnpacked` was removed from CDP, and local CRX install is
  blocked on macOS), so pin / group state isn't reproduced automatically.
  Right-click any tab → "Pin tab" once and Chrome remembers across launches.
- **Today tabs** (the unpinned section above pinned) become regular open
  Chrome tabs after the pinned ones.

`session.restore_on_startup` is set to "Continue where you left off" in the
migrated profile so those tabs come back every time you launch Chrome.

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

| Kind        | Portable artefact                       | Chromium direct migration                                                                                                            | Firefox direct migration              |
|-------------|-----------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------|
| Favorites   | (in NETSCAPE `bookmarks.html`)          | Chrome bookmark bar (flat, mirrors Arc's icon strip)                                                                                 | `bookmarks.html` placed in `imports/` |
| Pinned tabs | (in NETSCAPE `bookmarks.html`)          | Open Chrome tabs (leftmost in tab strip; pinning blocked by Chrome 142+ for external tools, right-click → Pin tab)                   | `bookmarks.html` placed in `imports/` |
| Today tabs  | OneTab / Toby-compatible JSON           | Open Chrome tabs (`session.restore_on_startup=1` so they come back next launch)                                                      | JSON placed in `imports/`             |
| Passwords   | `passwords.csv` (chmod 600)             | Re-encrypted into target `Login Data`                                                                                                | CSV placed in `imports/`              |
| Cards       | Reference CSV (last 4 digits only)      | Re-encrypted into target `Web Data`                                                                                                  | —                                     |
| Cookies     | Firefox `cookies.sqlite` + JSON         | Re-encrypted in-place in target `Cookies`                                                                                            | `cookies.sqlite` placed in `imports/` |
| Extensions  | HTML report with Chrome Web Store links | Web Store delivers fresh, Google-signed CRX bundles via External Extensions descriptors; per-extension storage carried over from Arc | `policies.json` for force-install     |
| History     | JSON + HTML                             | Copied as-is (plaintext)                                                                                                             | —                                     |
| Easels/Notes| Markdown (best-effort scrape)           | —                                                                                                                                    | —                                     |

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

## How extension migration works

Migrating Chromium extensions directly is harder than it looks. Chromium
runs two independent integrity checks against every installed extension:

- **Preference integrity.** Each entry in `extensions.settings.<id>` is
  HMAC-SHA256-signed against the browser's vendor seed + machine device ID
  and stored in `Secure Preferences`. Any tampering trips a reset that
  garbage-collects the offending entry.
- **Content verification.** Each extension's on-disk files are hashed and
  matched against the signed `_metadata/verified_contents.json` shipped by
  the Web Store. Mismatched hashes flag the extension as
  `DISABLE_CORRUPTED` (reason 1024) and Chromium aggressively
  garbage-collects the folder.

We can satisfy the first by resigning HMACs for the target's seed (the
device ID is shared since both browsers run on the same machine). But we
cannot satisfy the second: Arc patches several extensions (older versions
pinned, sidebar-aware content scripts), so its on-disk binaries no longer
match Google's signed hashes and Chrome rejects every one of them.

`arc-exporter migrate` therefore mixes the two approaches:

1. **Profile-tree copy** brings over everything *except* `Extensions/`.
   Storage directories (`Local Extension Settings`, `Sync Extension
   Settings`, `Extension State`, `Extension Rules`, …) ride along so the
   user's per-extension state survives the round trip.
2. **Strip stale extension registrations** from the copied `Preferences` /
   `Secure Preferences`. Arc's entries pointed at paths that no longer
   exist (we didn't copy them); leaving them in place would have Chrome
   fight ghost registrations forever.
3. **Resign the cleaned preferences** against the target browser's vendor
   seed using a Python port of Chromium's `pref_hash_calculator.cc`. This
   makes the surviving tracked prefs (`profile.name`, default search
   engine, …) survive the round trip too.
4. **Trigger a fresh Web Store install** by writing one `<id>.json`
   descriptor per extension into the target browser's `External
   Extensions/` directory (pointing at `clients2.google.com/service/update2/
   crx`), briefly launching the target browser with
   `--profile-directory=Profile N`, and waiting for each extension's folder
   to materialise in `Extensions/`.
5. **Clean up.** Terminate the target browser and remove the `External
   Extensions/` descriptors so they don't apply to other profiles on the
   user's next manual launch.

The downloaded CRX bundles are signed by Google, so content verification
passes on the next launch and extensions appear in the browser's UI
ready to use — with their per-extension storage intact. Extensions that
have been delisted from the Web Store are reported in the migration
summary; the HTML extension report next to each migrated profile is kept
as a manual-reinstall fallback for those and for sideloaded / developer
extensions that never had a Web Store entry.

The HMAC algorithm and per-vendor seeds live in
`arc_exporter/targets/secure_prefs.py` with citations to Chromium's
`pref_hash_calculator.cc` and the *HMAC and "Secure Preferences":
Revisiting Chromium-based Browsers Security* paper (Picazo-Sanchez et al.,
CANS 2020).

## Contributing

Issues and PRs welcome. Please don't open public issues for security
vulnerabilities; use the private channel in [SECURITY.md](SECURITY.md).

## Licence

MIT. See [LICENSE](LICENSE).
