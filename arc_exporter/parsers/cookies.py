"""Read Chromium ``Cookies`` SQLite into a typed iterator."""

from __future__ import annotations

import shutil
import sqlite3
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CookieRow:
    host: str
    name: str
    value: str
    encrypted_value: bytes
    path: str
    expires_utc: int
    creation_utc: int
    last_access_utc: int
    is_secure: bool
    is_httponly: bool
    samesite: int


def iter_cookies(cookies_db: Path) -> Iterable[CookieRow]:
    if not cookies_db.exists():
        return
    with tempfile.TemporaryDirectory(prefix="arc-export-cookies-") as td:
        copy = Path(td) / cookies_db.name
        shutil.copy2(cookies_db, copy)
        conn = sqlite3.connect(f"file:{copy}?mode=ro", uri=True)
        conn.text_factory = bytes
        conn.row_factory = sqlite3.Row
        try:
            try:
                cur = conn.execute(
                    "SELECT host_key, name, value, encrypted_value, path, expires_utc, "
                    "is_secure, is_httponly, samesite, creation_utc, last_access_utc "
                    "FROM cookies"
                )
            except sqlite3.OperationalError:
                return
            for r in cur:
                yield CookieRow(
                    host=_b2s(r["host_key"]),
                    name=_b2s(r["name"]),
                    value=_b2s(r["value"]),
                    encrypted_value=bytes(r["encrypted_value"])
                    if isinstance(r["encrypted_value"], (bytes, bytearray))
                    else b"",
                    path=_b2s(r["path"]) or "/",
                    expires_utc=int(_b2s(r["expires_utc"]) or 0),
                    creation_utc=int(_b2s(r["creation_utc"]) or 0),
                    last_access_utc=int(_b2s(r["last_access_utc"]) or 0),
                    is_secure=bool(int(_b2s(r["is_secure"]) or 0)),
                    is_httponly=bool(int(_b2s(r["is_httponly"]) or 0)),
                    samesite=int(_b2s(r["samesite"]) or 0),
                )
        finally:
            conn.close()


def _b2s(x) -> str:
    if isinstance(x, (bytes, bytearray)):
        return x.decode("utf-8", errors="ignore")
    return "" if x is None else str(x)
