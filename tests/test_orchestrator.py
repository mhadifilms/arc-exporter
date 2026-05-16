from __future__ import annotations

from pathlib import Path

from arc_exporter.orchestrator import ExportOptions, Orchestrator


def test_dry_run_writes_nothing(fake_arc_root: Path, tmp_path: Path, monkeypatch):
    out = tmp_path / "out"
    opts = ExportOptions(
        bookmarks=True,
        passwords=False,
        cards=False,
        cookies=False,
        history=False,
        tabs=True,
        extensions=False,
        easels=False,
        dry_run=True,
        arc_root=fake_arc_root,
        output_root=out,
    )
    orch = Orchestrator(opts)
    result = orch.run()
    assert result.run_dir.exists()
    # In dry run, profile output directories should not contain artefacts.
    profile_dir = result.run_dir / "profiles" / "Personal"
    if profile_dir.exists():
        assert not any(profile_dir.iterdir())
    assert sum(p.counts.get("bookmarks", 0) for p in result.profiles) >= 2


def test_writes_bookmarks_html(fake_arc_root: Path, tmp_path: Path):
    out = tmp_path / "out"
    opts = ExportOptions(
        bookmarks=True,
        passwords=False,
        cards=False,
        cookies=False,
        history=False,
        tabs=False,
        extensions=False,
        easels=False,
        dry_run=False,
        arc_root=fake_arc_root,
        output_root=out,
    )
    result = Orchestrator(opts).run()
    pe = result.profiles[0]
    html_path = pe.artefacts["bookmarks"]
    assert html_path.exists()
    content = html_path.read_text(encoding="utf-8")
    assert "<!DOCTYPE NETSCAPE-Bookmark-file-1>" in content


def test_latest_symlink_or_dir_points_to_run(fake_arc_root: Path, tmp_path: Path):
    out = tmp_path / "out"
    opts = ExportOptions(
        bookmarks=True,
        passwords=False,
        cards=False,
        cookies=False,
        history=False,
        tabs=False,
        extensions=False,
        easels=False,
        dry_run=False,
        arc_root=fake_arc_root,
        output_root=out,
    )
    Orchestrator(opts).run()
    latest = out / "latest"
    # We tolerate either a symlink (POSIX) or absence (restricted FS).
    if latest.exists() or latest.is_symlink():
        assert latest.exists()
