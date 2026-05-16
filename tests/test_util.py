from __future__ import annotations

import os
from pathlib import Path

import pytest

from arc_exporter.util import (
    chromium_microseconds_to_unix,
    chromium_time_now_microseconds,
    open_private,
    safe_copy_tree,
    safe_dir_name,
)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("hello", "hello"),
        ("  spaced  name  ", "spaced name"),
        ("bad/name:with*chars", "bad-name-with-chars"),
        ("", "profile"),
        (None, "profile"),
        ("CON", "CON-"),  # Windows reserved name
        ("...", "profile"),
        ("name." + "a" * 200, "name." + "a" * 115),
    ],
)
def test_safe_dir_name(raw, expected):
    assert safe_dir_name(raw) == expected


def test_open_private_creates_file_with_600(tmp_path: Path):
    f = tmp_path / "secret.txt"
    with open_private(f, "w") as fh:
        fh.write("data")
    if os.name == "posix":
        mode = f.stat().st_mode & 0o777
        assert mode == 0o600
    assert f.read_text() == "data"


def test_chromium_time_round_trip():
    us = chromium_time_now_microseconds()
    unix = chromium_microseconds_to_unix(us)
    assert unix > 0
    assert chromium_microseconds_to_unix(None) == 0
    assert chromium_microseconds_to_unix(0) == 0


def test_safe_copy_tree_skips_listed_names(tmp_path: Path):
    src = tmp_path / "src"
    (src / "Cache").mkdir(parents=True)
    (src / "Cache" / "big.bin").write_bytes(b"x" * 1024)
    (src / "Preferences").write_text("{}")
    dst = tmp_path / "dst"
    final = safe_copy_tree(src, dst, skip=("Cache",))
    assert final == dst
    assert (final / "Preferences").exists()
    assert not (final / "Cache").exists()
