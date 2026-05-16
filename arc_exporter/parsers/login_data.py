"""Read Chromium ``Login Data`` SQLite into a typed iterator."""

from __future__ import annotations

import shutil
import sqlite3
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from arc_exporter.errors import CorruptDataError


@dataclass(frozen=True)
class LoginRow:
    origin_url: str
    username: str
    password_blob: bytes


def iter_logins(login_data: Path) -> Iterable[LoginRow]:
    """Yield :class:`LoginRow` from a Chromium ``Login Data`` SQLite file.

    The file is copied to a private temp dir first because Chromium may have an exclusive
    SQLite lock on the live file. The copy is removed before this generator exits.
    """
    if not login_data.exists():
        return
    with tempfile.TemporaryDirectory(prefix="arc-export-login-") as td:
        copy = Path(td) / login_data.name
        shutil.copy2(login_data, copy)
        try:
            conn = sqlite3.connect(f"file:{copy}?mode=ro", uri=True)
            conn.row_factory = sqlite3.Row
        except sqlite3.Error as e:
            raise CorruptDataError(f"could not open Login Data: {e}") from e
        try:
            try:
                cur = conn.execute("SELECT origin_url, username_value, password_value FROM logins")
            except sqlite3.OperationalError as e:
                raise CorruptDataError(f"Login Data schema unsupported: {e}") from e
            for r in cur:
                url = r["origin_url"] or ""
                user = r["username_value"] or ""
                pw = r["password_value"]
                yield LoginRow(
                    origin_url=str(url),
                    username=str(user),
                    password_blob=bytes(pw) if isinstance(pw, (bytes, bytearray)) else b"",
                )
        finally:
            conn.close()
