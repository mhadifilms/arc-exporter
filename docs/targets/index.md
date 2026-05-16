# Per-browser guides

`arc-exporter` supports four families of browsers. The matrix below summarises
what each one accepts.

| Target       | Family    | Bookmarks | Passwords | Cards | Cookies | Extensions |
|--------------|-----------|:---------:|:---------:|:-----:|:-------:|:----------:|
| Chrome       | Chromium  | ✓         | ✓         | ✓     | ✓       | ✓ (report) |
| Brave        | Chromium  | ✓         | ✓         | ✓     | ✓       | ✓ (report) |
| Edge         | Chromium  | ✓         | ✓         | ✓     | ✓       | ✓ (report) |
| Vivaldi      | Chromium  | ✓         | ✓         | ✓     | ✓       | ✓ (report) |
| Opera        | Chromium  | ✓         | ✓         | ✓     | ✓       | ✓ (report) |
| Dia          | Chromium  | ✓         | ✓         | ✓     | ✓       | ✓ (report) |
| Arc Search   | Chromium  | ✓         | ✓         | ✓     | ✓       | ✓ (report) |
| Sidekick     | Chromium  | ✓         | ✓         | ✓     | ✓       | ✓ (report) |
| Comet        | Chromium  | ✓         | ✓         | ✓     | ✓       | ✓ (report) |
| Firefox      | Firefox   | ✓         | ✓         | —     | ✓       | ✓ (policy) |
| Zen          | Firefox   | ✓         | ✓         | —     | ✓       | ✓ (policy) |
| LibreWolf    | Firefox   | ✓         | ✓         | —     | ✓       | ✓ (policy) |
| Floorp       | Firefox   | ✓         | ✓         | —     | ✓       | ✓ (policy) |
| Waterfox     | Firefox   | ✓         | ✓         | —     | ✓       | ✓ (policy) |
| Safari       | Safari    | ✓         | ✓         | —     | —       | —          |
| Orion        | Orion     | ✓         | ✓         | —     | —       | —          |

Chromium "Extensions" support means a per-profile HTML report with Chrome Web
Store links. Automated extension install is intentionally *not* attempted —
Chrome's integrity checks make that unreliable and earlier versions of
`arc-exporter` cross-polluted other Chrome profiles when they tried.

Firefox "Extensions" support means a generated `policies.json` that
force-installs each matched add-on (managed mode).
