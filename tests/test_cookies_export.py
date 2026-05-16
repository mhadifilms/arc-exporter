from __future__ import annotations

import sqlite3
from pathlib import Path

from arc_exporter.export.cookies_sqlite import write_cookies_sqlite
from arc_exporter.parsers.cookies import iter_cookies


def test_writes_moz_cookies_schema(tmp_path: Path, fake_cookies: Path):
    out = tmp_path / "cookies.sqlite"
    n = write_cookies_sqlite(out, iter_cookies(fake_cookies), aes_key=None)
    assert n == 1
    conn = sqlite3.connect(str(out))
    try:
        row = conn.execute("SELECT host, name, value, isSecure, isHttpOnly FROM moz_cookies").fetchone()
    finally:
        conn.close()
    assert row[0] == "example.com"
    assert row[1] == "session"
    assert row[2] == "abc123"
    assert row[3] == 1
    assert row[4] == 1
