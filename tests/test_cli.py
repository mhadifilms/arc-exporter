from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from arc_exporter.cli import app


def _runner() -> CliRunner:
    # Force a wide terminal so Rich tables don't truncate our assertion strings.
    import os

    os.environ["COLUMNS"] = "200"
    os.environ["TERM"] = "dumb"
    return CliRunner()


def test_version_command():
    r = _runner().invoke(app, ["version"])
    assert r.exit_code == 0
    assert r.stdout.strip()


def test_targets_command():
    r = _runner().invoke(app, ["targets"])
    assert r.exit_code == 0
    assert "chrome" in r.stdout.lower()
    assert "firefox" in r.stdout.lower()


def test_export_bookmarks_dry_run(fake_arc_root: Path, tmp_path: Path):
    r = _runner().invoke(
        app,
        [
            "export",
            "bookmarks",
            "--dry-run",
            "--arc-root",
            str(fake_arc_root),
            "--output",
            str(tmp_path / "out"),
            "--force",
        ],
    )
    assert r.exit_code == 0, r.output
    assert "Export run" in r.output
    assert "out/runs/" in r.output


def test_list_command(fake_arc_root: Path):
    r = _runner().invoke(app, ["list", "--arc-root", str(fake_arc_root)])
    assert r.exit_code == 0
    assert "Default" in r.output
