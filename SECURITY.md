# Security policy

## Reporting a vulnerability

If you find a security vulnerability in arc-exporter — anything that could leak passwords,
cookies, payment cards, or browser session data — please report it privately.

- Email: security@example.invalid (placeholder; replace before public launch)
- GitHub: use the "Report a vulnerability" link under the Security tab to open a private
  advisory.

Please include:

1. A description of the issue and its impact.
2. Reproduction steps (preferably against the in-repo fixtures, not real user data).
3. The arc-exporter version and OS.

We aim to acknowledge reports within 72 hours and to ship a fix within 14 days for
high-severity issues.

## Scope

In scope:

- Anything that writes plaintext credentials, cookies, or PANs to disk in an unintended
  location or with permissive permissions.
- Anything that mutates a target browser's data while that browser is running, risking
  corruption.
- Anything that interpolates user-controlled data into shell commands or HTML/CSV without
  escaping.
- Network calls that disable certificate validation or leak telemetry.

Out of scope:

- Vulnerabilities in third-party browsers themselves.
- Issues that require root / Full Disk Access already being granted to a malicious local
  process.

## Hardening defaults

arc-exporter:

- Never writes decrypted passwords or PANs to disk in temporary files. All crypto is
  in-process via `cryptography`.
- `chmod 0o600` every file containing credentials or session data immediately after
  creation.
- HTML-escapes every user-controlled string before emitting bookmark / extension HTML.
- Refuses to mutate a target browser's data while that browser is running, unless
  `--force` is passed.
- Treats the source Arc data as read-only.
