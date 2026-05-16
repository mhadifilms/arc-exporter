"""Read Chromium ``Web Data`` SQLite (credit cards and form autofill)."""

from __future__ import annotations

import shutil
import sqlite3
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class CardRow:
    name_on_card: str
    expiration_month: int
    expiration_year: int
    card_number_encrypted: bytes
    last_four: str = ""


def iter_credit_cards(web_data: Path) -> Iterable[CardRow]:
    """Yield :class:`CardRow` from ``Web Data``; tolerant of schema variations."""
    if not web_data.exists():
        return
    with tempfile.TemporaryDirectory(prefix="arc-export-webdata-") as td:
        copy = Path(td) / web_data.name
        shutil.copy2(web_data, copy)
        conn = sqlite3.connect(f"file:{copy}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            for query in (
                "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, '' AS last_four FROM credit_cards",
                "SELECT name_on_card, expiration_month, expiration_year, card_number_encrypted, last_four FROM masked_credit_cards",
                "SELECT name_on_card, expiration_month, expiration_year, '' AS card_number_encrypted, last_four FROM masked_credit_cards",
            ):
                try:
                    cur = conn.execute(query)
                except sqlite3.OperationalError:
                    continue
                for r in cur:
                    enc = r["card_number_encrypted"]
                    yield CardRow(
                        name_on_card=str(r["name_on_card"] or ""),
                        expiration_month=int(r["expiration_month"] or 0),
                        expiration_year=int(r["expiration_year"] or 0),
                        card_number_encrypted=bytes(enc) if isinstance(enc, (bytes, bytearray)) else b"",
                        last_four=str(r["last_four"] or ""),
                    )
                return
        finally:
            conn.close()
