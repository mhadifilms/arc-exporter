from __future__ import annotations

import csv
import os
from pathlib import Path

from arc_exporter.export.passwords_csv import write_passwords_csv
from arc_exporter.parsers.login_data import iter_logins


def test_writes_csv_with_decrypted_passwords(tmp_path: Path, fake_login_data: Path, aes_key: bytes):
    out = tmp_path / "passwords.csv"
    written, failed = write_passwords_csv(out, iter_logins(fake_login_data), aes_key=aes_key)
    assert written == 2
    assert failed == 1
    if os.name == "posix":
        assert out.stat().st_mode & 0o777 == 0o600
    with out.open("r", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    assert rows[0] == ["name", "url", "username", "password", "note"]
    passwords = {r[2]: r[3] for r in rows[1:] if r[3]}
    assert passwords["alice@example.com"] == "p@ss-1"
    assert passwords["bob"] == "hunter2"
    # The non-v10 row must produce an empty password, never raw bytes.
    bad_row = next(r for r in rows[1:] if r[2] == "carol")
    assert bad_row[3] == ""
    assert "no Safe Storage" in bad_row[4] or "not a v10" in bad_row[4]


def test_writes_csv_no_key(tmp_path: Path, fake_login_data: Path):
    out = tmp_path / "passwords.csv"
    written, failed = write_passwords_csv(out, iter_logins(fake_login_data), aes_key=None)
    assert written == 0
    assert failed >= 2
    with out.open("r", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    for r in rows[1:]:
        assert r[3] == ""
