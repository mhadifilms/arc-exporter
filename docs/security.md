# Security & privacy

`arc-exporter` is a local tool. It does not phone home, does not bundle telemetry,
and does not need network access except optionally to fetch the Chrome→AMO
extension mapping from `addons.mozilla.org`.

## Threat model

The user's threats are roughly:

1. **A malicious local process** reads the temp files / output files arc-exporter
   creates.
2. **A malicious bookmark or extension** injects script into the exported HTML the
   user opens in their new browser.
3. **arc-exporter corrupts the target browser's databases** by writing while the
   browser holds a SQLite lock.

The defaults below are designed for those.

## What touches disk in plaintext

| Data            | On disk? | Notes |
|-----------------|----------|-------|
| Arc password ciphertext | yes (Arc owns it; we read only) | unmodified, read-only copy in a private temp dir |
| Arc password plaintext  | **no**  | decrypted in memory; never written to a temp file |
| Exported passwords CSV  | yes (`0o600`) | `name,url,username,password,note` |
| Card PAN                | **no**  | decrypted in memory only to take `last4`; never written |
| Card last4 CSV          | yes (`0o600`) | reference only |
| Cookies (if you opt in) | yes (`0o600`) | Firefox `cookies.sqlite` + JSON |
| Bookmarks HTML          | yes      | every title / URL HTML-escaped |
| Extensions HTML report  | yes      | every name HTML-escaped |

## What we will never do

- Shell out to `openssl` with credentials on the command line.
- Write decrypted plaintext to temp files (the old code did; we replaced it with
  in-process `cryptography` AES-CBC).
- Mutate target-browser SQLite while the target browser is running.
- Touch your Arc data directory destructively. Reading happens through `mode=ro`
  SQLite URIs against a temp copy of each database.
- Disable certificate validation on the AMO mapping fetch.

## Reporting a vulnerability

See [SECURITY.md](https://github.com/mhadifilms/arc-exporter/blob/main/SECURITY.md)
in the repo. Please do not open public issues for security problems.
