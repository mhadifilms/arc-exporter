"""Write cookies in Firefox's ``cookies.sqlite`` (``moz_cookies``) schema."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from pathlib import Path

from arc_exporter.crypto import decrypt_v10, looks_like_v10
from arc_exporter.errors import CryptoError
from arc_exporter.parsers.cookies import CookieRow
from arc_exporter.util import chmod_private, chromium_microseconds_to_unix

_SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS moz_cookies (
    id INTEGER PRIMARY KEY,
    originAttributes TEXT NOT NULL DEFAULT '',
    name TEXT,
    value TEXT,
    host TEXT,
    path TEXT,
    expiry INTEGER,
    lastAccessed INTEGER,
    creationTime INTEGER,
    isSecure INTEGER,
    isHttpOnly INTEGER,
    inBrowserElement INTEGER DEFAULT 0,
    sameSite INTEGER,
    rawSameSite INTEGER DEFAULT 0,
    schemeMap INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS moz_basedomain ON moz_cookies (host);
"""


def write_cookies_sqlite(
    out_path: Path,
    cookies: Iterable[CookieRow],
    *,
    aes_key: bytes | None,
) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        out_path.unlink()
    conn = sqlite3.connect(str(out_path))
    try:
        conn.executescript(_SCHEMA)
        n = 0
        for c in cookies:
            value = c.value
            if not value and c.encrypted_value and aes_key is not None and looks_like_v10(c.encrypted_value):
                try:
                    value = decrypt_v10(c.encrypted_value, aes_key)
                except CryptoError:
                    value = ""
            conn.execute(
                "INSERT INTO moz_cookies (originAttributes, name, value, host, path, expiry, "
                "lastAccessed, creationTime, isSecure, isHttpOnly, sameSite) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    "",
                    c.name,
                    value,
                    c.host,
                    c.path,
                    chromium_microseconds_to_unix(c.expires_utc),
                    int(chromium_microseconds_to_unix(c.last_access_utc) * 1e6),
                    int(chromium_microseconds_to_unix(c.creation_utc) * 1e6),
                    1 if c.is_secure else 0,
                    1 if c.is_httponly else 0,
                    c.samesite,
                ),
            )
            n += 1
        conn.commit()
    finally:
        conn.close()
    chmod_private(out_path)
    return n
