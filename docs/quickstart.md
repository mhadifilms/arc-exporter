# Quick start

Quit Arc and the target browser first. The rest is five commands.

## 1. Doctor

```bash
arc-exporter doctor
```

`doctor` checks every prerequisite — Python version, Arc installed, Keychain
accessible, browsers not running, disk space, target browsers detected. Anything
red has a short, specific fix in [troubleshooting](troubleshooting.md).

## 2. List Arc profiles

```bash
arc-exporter list
```

You'll see the profiles `arc-exporter` will operate on. Note that Arc's hidden
`__ARC_SYSTEM_PROFILE` is always filtered out.

## 3. Export everything portable

```bash
arc-exporter export all
```

Writes to `./arc-export/runs/<timestamp>/profiles/<ProfileName>/`:

- `bookmarks_<ts>.html`     (NETSCAPE; any browser can import)
- `passwords_<ts>.csv`      (`chmod 0600`)
- `cards_<ts>.csv`          (last 4 digits only — full PAN never written)
- `extensions_<ts>.html`    (Chrome WS + AMO links)

Add `--cookies`, `--history`, `--tabs`, `--easels`, `--amo-mapping` for more.

## 4. Or migrate directly into another browser

```bash
arc-exporter migrate --to=brave
```

Replace `brave` with any supported target (`arc-exporter targets` lists them).

`migrate` runs the export first, then hands the artefacts to the chosen target's
adapter. The target *never* gets your Arc Safe Storage key — passwords are
re-encrypted with the target's own key on the way in.

## 5. (Optional) Restore if something went sideways

Every file `arc-exporter` overwrites is backed up with a unique ID first:

```bash
arc-exporter backup ls
arc-exporter backup restore <id>
```

## Flags you'll actually use

| Flag                  | Meaning                                                                 |
|-----------------------|-------------------------------------------------------------------------|
| `--dry-run`           | Plan the run; write nothing.                                            |
| `-v` / `-vv`          | Verbose / debug logging on stderr.                                      |
| `--force`             | Bypass the "browsers must be quit" guard (you know best).               |
| `--arc-root <path>`   | Override the auto-detected Arc data directory (useful for testing).     |
| `--output <path>`     | Override `./arc-export/`.                                               |
| `--only <kinds>`      | Comma-separated subset for `migrate`, e.g. `--only=bookmarks,passwords`.|
