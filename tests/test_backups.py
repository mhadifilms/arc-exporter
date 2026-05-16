from __future__ import annotations

from pathlib import Path

import pytest

from arc_exporter.guards.backups import BackupManager


def test_backup_and_restore(tmp_path: Path):
    target = tmp_path / "file.txt"
    target.write_text("original", encoding="utf-8")
    mgr = BackupManager(tmp_path / "backups")
    entry = mgr.back_up(target, description="test")
    assert entry is not None
    target.write_text("modified", encoding="utf-8")
    restored = mgr.restore(entry.backup_id)
    assert Path(restored.original).read_text() == "original"


def test_missing_file_returns_none(tmp_path: Path):
    mgr = BackupManager(tmp_path / "b")
    assert mgr.back_up(tmp_path / "nope") is None


def test_unknown_restore_id(tmp_path: Path):
    mgr = BackupManager(tmp_path / "b")
    with pytest.raises(FileNotFoundError):
        mgr.restore("nope")


def test_prune_keeps_latest(tmp_path: Path):
    target = tmp_path / "file.txt"
    mgr = BackupManager(tmp_path / "b")
    target.write_text("v1")
    mgr.back_up(target)
    target.write_text("v2")
    mgr.back_up(target)
    target.write_text("v3")
    mgr.back_up(target)
    removed = mgr.prune(keep_per_file=1)
    assert removed == 2
    assert len(mgr.list_entries()) == 1
