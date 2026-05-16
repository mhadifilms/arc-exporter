from __future__ import annotations

import json
from pathlib import Path

from arc_exporter.export.extensions_html import write_extensions_html
from arc_exporter.parsers.extensions import Extension, from_filesystem, from_preferences, list_extensions


def _make_profile(tmp_path: Path, prefs: dict, fs_exts: dict[str, dict]) -> Path:
    p = tmp_path / "Profile"
    p.mkdir()
    (p / "Preferences").write_text(json.dumps(prefs), encoding="utf-8")
    ext_root = p / "Extensions"
    for ext_id, manifest in fs_exts.items():
        v = ext_root / ext_id / "1.0"
        v.mkdir(parents=True)
        (v / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return p


def test_preferences_drops_themes_and_disabled(tmp_path: Path):
    p = _make_profile(
        tmp_path,
        prefs={
            "extensions": {
                "settings": {
                    "aaaa": {"state": 1, "manifest": {"name": "Real", "version": "1"}},
                    "bbbb": {"state": 0, "manifest": {"name": "Disabled", "version": "1"}},
                    "tttt": {"state": 1, "manifest": {"name": "Theme", "version": "1", "theme": {}}},
                }
            }
        },
        fs_exts={},
    )
    names = {e.name for e in from_preferences(p)}
    assert "Real" in names
    assert "Theme" not in names
    enabled = {e.name: e.enabled for e in from_preferences(p)}
    assert enabled["Real"] is True
    assert enabled["Disabled"] is False


def test_filesystem_picks_latest_version_and_resolves_i18n(tmp_path: Path):
    # __MSG_ name resolution from _locales
    p = tmp_path / "Profile"
    p.mkdir()
    v = p / "Extensions" / "xxxx" / "2.5"
    v.mkdir(parents=True)
    (v / "manifest.json").write_text(
        json.dumps({"name": "__MSG_extName__", "version": "2.5", "default_locale": "en"}),
        encoding="utf-8",
    )
    (v / "_locales" / "en").mkdir(parents=True)
    (v / "_locales" / "en" / "messages.json").write_text(
        json.dumps({"extName": {"message": "My Cool Extension"}}),
        encoding="utf-8",
    )
    fs = from_filesystem(p)
    assert fs[0].name == "My Cool Extension"


def test_list_extensions_merges_and_dedupes(tmp_path: Path):
    p = _make_profile(
        tmp_path,
        prefs={
            "extensions": {
                "settings": {
                    "id1": {"state": 1, "manifest": {"name": "PrefsName", "version": "1.0"}},
                }
            }
        },
        fs_exts={"id1": {"name": "FSName", "version": "1.1"}, "id2": {"name": "OnlyFS"}},
    )
    merged = {e.chrome_id: e.name for e in list_extensions(p)}
    assert merged["id1"] == "FSName"
    assert merged["id2"] == "OnlyFS"


def test_extensions_html_escapes_names(tmp_path: Path):
    out = tmp_path / "x.html"
    exts = [
        Extension(chrome_id="xxx", name="<script>alert(1)</script>", version="1", homepage_url="javascript:1")
    ]
    write_extensions_html(out, exts, profile_name="Profile<dangerous>")
    content = out.read_text()
    assert "<script>alert(1)</script>" not in content
    assert "&lt;script&gt;" in content
    assert "Profile&lt;dangerous&gt;" in content
