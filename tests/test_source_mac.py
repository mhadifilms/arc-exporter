from __future__ import annotations

from pathlib import Path

import pytest

from arc_exporter.errors import ArcNotFoundError
from arc_exporter.source.arc_macos import ArcSourceMac


def test_lists_profile_and_skips_system(fake_arc_root: Path):
    src = ArcSourceMac(fake_arc_root)
    profiles = src.profiles()
    assert len(profiles) == 1
    p = profiles[0]
    assert p.directory_name == "Default"
    assert p.display_name == "Personal"


def test_raises_when_arc_missing(tmp_path: Path):
    src = ArcSourceMac(tmp_path / "missing")
    with pytest.raises(ArcNotFoundError):
        src.profiles()
