# Troubleshooting

## `Keychain accessible: FAIL` in `doctor`

You probably never opened Arc on this Mac, or you cleared its Keychain entry.

```bash
security find-generic-password -s "Arc Safe Storage"   # expected: prints metadata
```

Open Arc once, sign in, sync at least one password, quit Arc, re-run `doctor`.

## `Browsers quit: FAIL`

Quit Arc *and* the target browser (`Cmd+Q` on macOS, `End Task` on Windows).
arc-exporter refuses to mutate a browser's data while it's running.

If you really want to proceed (e.g. a non-mutating `export bookmarks`), pass
`--force`.

## Safari import doesn't see my passwords

Safari requires Full Disk Access for the calling process. `doctor` flags this; in
**System Settings → Privacy & Security → Full Disk Access**, add your terminal
emulator (or the `.command` launcher) and rerun.

## Output dir filled up

Every run writes to `arc-export/runs/<timestamp>/`. The `latest` symlink always
points at the most recent run. To recover space: `arc-exporter backup prune`
(coming in 0.3) or `rm -rf arc-export/runs/<old-timestamp>` manually.

## Chrome shows "Profile may have been used by another version" after migrate

We mark migrated profiles `exit_type=Normal` to suppress that warning, but Chrome
occasionally still shows it on first launch. Click "Continue without signing in";
the warning will not return.

## `IndexedDB` / `Local Storage` was kept and now the new Chrome is huge

By default we keep web-app storage so signed-in sessions survive. To produce a
slim profile copy, pass `--strip-storage`.

## I migrated to Brave but Brave keeps marking the imported profile "Guest"

This usually means Brave was running when `register_chrome_profile` patched its
`Local State` — re-quit Brave, restart it, and the profile picker will show the
right entry.

## Where is the verbose log?

Pass `-vv`. By default everything goes to stderr so you can `2>` redirect.
