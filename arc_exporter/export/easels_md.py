"""Best-effort export of Arc Easels / Notes to Markdown.

Arc's easels and notes are stored in a private SQLite + JSON tree that has changed
across versions. We:

1. Walk every JSON blob under the Arc profile that has an ``easels`` or ``notes`` key.
2. Extract whatever text content we can.
3. Write one Markdown file per profile with each easel/note as a section.

This is intentionally lossy. The goal is "do not silently drop the user's notes" — a
formatted PDF-style export is out of scope.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path


def collect_easel_notes(profile_dir: Path) -> Iterable[dict]:
    """Yield ``{title, body, kind}`` records found in JSON files under ``profile_dir``."""
    candidates = [
        profile_dir / "Easels",
        profile_dir / "Notes",
        profile_dir / "ARC" / "Easels",
        profile_dir / "ARC" / "Notes",
    ]
    for root in candidates:
        if not root.is_dir():
            continue
        for json_file in root.rglob("*.json"):
            try:
                data = json.loads(json_file.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            yield from _walk_records(data)


def write_easels_md(out_path: Path, records: Iterable[dict]) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# Arc Easels & Notes\n"]
    n = 0
    for r in records:
        title = r.get("title") or "(untitled)"
        kind = r.get("kind") or "note"
        body = r.get("body") or ""
        lines.append(f"\n## [{kind}] {title}\n\n{body}\n")
        n += 1
    out_path.write_text("".join(lines), encoding="utf-8")
    return n


def _walk_records(obj) -> Iterable[dict]:
    if isinstance(obj, dict):
        title = obj.get("title") or obj.get("name")
        body = obj.get("body") or obj.get("content") or obj.get("text")
        kind = obj.get("type") or obj.get("kind")
        if isinstance(title, str) and isinstance(body, str):
            yield {"title": title, "body": body, "kind": kind or "note"}
        for v in obj.values():
            yield from _walk_records(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_records(v)
