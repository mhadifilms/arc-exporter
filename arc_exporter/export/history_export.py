"""History export to JSON and a simple HTML report."""

from __future__ import annotations

import datetime as dt
import html
import json
from collections.abc import Iterable
from pathlib import Path

from arc_exporter.parsers.history import HistoryRow
from arc_exporter.util import open_private


def write_history_json(out_path: Path, rows: Iterable[HistoryRow]) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload = [
        {
            "url": r.url,
            "title": r.title,
            "visit_count": r.visit_count,
            "typed_count": r.typed_count,
            "last_visit": r.last_visit_unix,
        }
        for r in rows
    ]
    with open_private(out_path, "w") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    return len(payload)


def write_history_html(out_path: Path, rows: Iterable[HistoryRow]) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Arc History</title>",
        "<style>body{font-family:system-ui,sans-serif;max-width:980px;margin:24px auto;padding:0 16px;}",
        "table{width:100%;border-collapse:collapse;font-size:14px}",
        "th,td{padding:6px 8px;border-bottom:1px solid #eee;text-align:left}",
        "th{position:sticky;top:0;background:#fff}a{color:#1a73e8;text-decoration:none}",
        "a:hover{text-decoration:underline}</style></head><body><h1>Arc History</h1><table>",
        "<thead><tr><th>Last visit</th><th>Title</th><th>URL</th><th>Visits</th></tr></thead><tbody>",
    ]
    n = 0
    for r in rows:
        ts = (
            dt.datetime.fromtimestamp(r.last_visit_unix).isoformat(timespec="seconds")
            if r.last_visit_unix
            else ""
        )
        parts.append(
            f"<tr><td>{html.escape(ts)}</td>"
            f"<td>{html.escape(r.title)}</td>"
            f"<td><a href='{html.escape(r.url, quote=True)}'>{html.escape(r.url)}</a></td>"
            f"<td>{r.visit_count}</td></tr>"
        )
        n += 1
    parts.append("</tbody></table></body></html>")
    with open_private(out_path, "w") as f:
        f.write("".join(parts))
    return n
