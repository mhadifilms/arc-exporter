"""Read Chromium ``History`` SQLite into a typed iterator."""

from __future__ import annotations

import shutil
import sqlite3
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from arc_exporter.util import chromium_microseconds_to_unix


@dataclass(frozen=True)
class HistoryRow:
    url: str
    title: str
    visit_count: int
    typed_count: int
    last_visit_unix: int


def iter_history(history_db: Path, *, limit: int | None = None) -> Iterable[HistoryRow]:
    if not history_db.exists():
        return
    with tempfile.TemporaryDirectory(prefix="arc-export-history-") as td:
        copy = Path(td) / history_db.name
        shutil.copy2(history_db, copy)
        conn = sqlite3.connect(f"file:{copy}?mode=ro", uri=True)
        conn.row_factory = sqlite3.Row
        try:
            q = "SELECT url, title, visit_count, typed_count, last_visit_time FROM urls ORDER BY last_visit_time DESC"
            if limit:
                q += f" LIMIT {int(limit)}"
            cur = conn.execute(q)
            for r in cur:
                yield HistoryRow(
                    url=str(r["url"] or ""),
                    title=str(r["title"] or ""),
                    visit_count=int(r["visit_count"] or 0),
                    typed_count=int(r["typed_count"] or 0),
                    last_visit_unix=chromium_microseconds_to_unix(r["last_visit_time"]),
                )
        finally:
            conn.close()
