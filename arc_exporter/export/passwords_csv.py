"""Write passwords to a CSV importable by Chrome / Brave / Firefox / Safari.

Output columns match Chrome's published format: ``name,url,username,password,note``.
File mode is forced to ``0o600`` from the moment of creation.
"""

from __future__ import annotations

import csv
from collections.abc import Iterable
from pathlib import Path
from urllib.parse import urlparse

from arc_exporter.crypto import decrypt_v10, looks_like_v10
from arc_exporter.errors import CryptoError
from arc_exporter.parsers.login_data import LoginRow
from arc_exporter.util import chmod_private, open_private

HEADER = ("name", "url", "username", "password", "note")


def _name_from_url(url: str) -> str:
    try:
        host = urlparse(url).hostname or url
    except ValueError:
        host = url
    return host.removeprefix("www.") if isinstance(host, str) else url


def write_passwords_csv(
    out_path: Path,
    logins: Iterable[LoginRow],
    *,
    aes_key: bytes | None,
) -> tuple[int, int]:
    """Write ``logins`` to ``out_path``; returns ``(rows_written, rows_failed)``.

    Rows whose ciphertext cannot be decrypted are written with an empty password and a
    ``note`` explaining why — never with raw ciphertext bytes.
    """
    out_path.parent.mkdir(parents=True, exist_ok=True)
    written = failed = 0
    with open_private(out_path, "w") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL)
        writer.writerow(HEADER)
        for row in logins:
            password = ""
            note = ""
            if looks_like_v10(row.password_blob) and aes_key is not None:
                try:
                    password = decrypt_v10(row.password_blob, aes_key)
                except CryptoError as e:
                    note = f"decrypt failed: {e}"
                    failed += 1
            elif row.password_blob:
                if aes_key is None:
                    note = "no Safe Storage key available; password not exported"
                else:
                    note = "not a v10 blob"
                failed += 1
            writer.writerow([_name_from_url(row.origin_url), row.origin_url, row.username, password, note])
            written += 1 if password else 0
    chmod_private(out_path)
    return written, failed
