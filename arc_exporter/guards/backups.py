"""Versioned, restorable backups for any file the package mutates.

Every backup is stored alongside the original with the suffix ``.bak-<timestamp>-<id>``.
The :class:`BackupManager` also keeps a JSON index at ``arc-export/backups.json`` so
``arc-exporter backup ls / restore`` can find them across runs.
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from pathlib import Path

from arc_exporter.util import chmod_private, ensure_dir, now_stamp, short_random


@dataclass(frozen=True)
class BackupEntry:
    backup_id: str
    timestamp: str
    original: str
    backup: str
    description: str


class BackupManager:
    """Maintain a JSON-indexed set of file backups."""

    INDEX_NAME = "backups.json"

    def __init__(self, index_dir: Path) -> None:
        self.index_dir = ensure_dir(index_dir)
        self.index_path = self.index_dir / self.INDEX_NAME

    def _load(self) -> list[BackupEntry]:
        if not self.index_path.exists():
            return []
        try:
            data = json.loads(self.index_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        return [BackupEntry(**row) for row in data]

    def _save(self, entries: list[BackupEntry]) -> None:
        payload = [asdict(e) for e in entries]
        self.index_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        chmod_private(self.index_path)

    def back_up(self, original: Path, *, description: str = "") -> BackupEntry | None:
        """Copy ``original`` to a uniquely-named backup file. Returns ``None`` if missing."""
        if not original.exists():
            return None
        bid = short_random(8)
        stamp = now_stamp()
        backup_path = original.with_name(f"{original.name}.bak-{stamp}-{bid}")
        shutil.copy2(original, backup_path)
        entry = BackupEntry(
            backup_id=bid,
            timestamp=stamp,
            original=str(original),
            backup=str(backup_path),
            description=description,
        )
        entries = self._load()
        entries.append(entry)
        self._save(entries)
        return entry

    def list_entries(self) -> list[BackupEntry]:
        return self._load()

    def restore(self, backup_id: str) -> BackupEntry:
        for e in self._load():
            if e.backup_id == backup_id:
                shutil.copy2(e.backup, e.original)
                return e
        raise FileNotFoundError(f"no backup with id {backup_id!r}")

    def prune(self, keep_per_file: int = 5) -> int:
        """Keep only the ``keep_per_file`` most recent backups per original path.

        Older backup files are removed from disk and from the index.
        """
        entries = self._load()
        by_orig: dict[str, list[BackupEntry]] = {}
        for e in entries:
            by_orig.setdefault(e.original, []).append(e)
        keep: list[BackupEntry] = []
        removed = 0
        for _orig, group in by_orig.items():
            group.sort(key=lambda e: e.timestamp, reverse=True)
            keep.extend(group[:keep_per_file])
            for stale in group[keep_per_file:]:
                try:
                    Path(stale.backup).unlink()
                    removed += 1
                except OSError:
                    pass
        self._save(keep)
        return removed


def backup_paths(
    paths: Iterable[Path], manager: BackupManager, *, description: str = ""
) -> list[BackupEntry]:
    """Convenience: back up many paths in one call."""
    entries: list[BackupEntry] = []
    for p in paths:
        e = manager.back_up(p, description=description)
        if e is not None:
            entries.append(e)
    return entries
