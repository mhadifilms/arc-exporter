from __future__ import annotations

import json
from pathlib import Path

from arc_exporter.export.bookmarks_chrome_json import (
    build_chrome_bookmarks,
    write_chrome_bookmarks,
)
from arc_exporter.parsers.sidebar import BookmarkNode, SpaceTree


def _sample_space() -> SpaceTree:
    leaf = BookmarkNode(title="Example", kind="bookmark", url="https://example.com/")
    folder = BookmarkNode(title="Inner", kind="folder", children=[leaf])
    return SpaceTree(name="Work", profile_dir="Default", pinned=[folder])


def test_build_has_chrome_schema():
    payload = build_chrome_bookmarks([_sample_space()])
    assert payload["version"] == 1
    roots = payload["roots"]
    assert set(roots) == {"bookmark_bar", "other", "synced"}
    bar = roots["bookmark_bar"]
    assert bar["type"] == "folder"
    assert bar["id"] == "1"
    assert len(bar["children"]) == 1  # one Space folder
    space_folder = bar["children"][0]
    assert space_folder["name"] == "Work"
    assert space_folder["type"] == "folder"
    assert space_folder["children"][0]["name"] == "Inner"
    leaf = space_folder["children"][0]["children"][0]
    assert leaf["type"] == "url"
    assert leaf["url"] == "https://example.com/"


def test_empty_space_is_omitted():
    empty = SpaceTree(name="Empty", profile_dir="Default", pinned=[])
    populated = _sample_space()
    payload = build_chrome_bookmarks([empty, populated])
    assert len(payload["roots"]["bookmark_bar"]["children"]) == 1


def test_write_creates_file_and_strips_bak(tmp_path: Path):
    dest = tmp_path / "Bookmarks"
    bak = tmp_path / "Bookmarks.bak"
    bak.write_text("stale", encoding="utf-8")
    n = write_chrome_bookmarks([_sample_space()], dest)
    assert n == 1
    assert dest.exists()
    assert not bak.exists()  # stale backup wiped so Chrome regenerates clean
    data = json.loads(dest.read_text())
    assert data["roots"]["bookmark_bar"]["children"][0]["name"] == "Work"


def test_unique_ids_within_payload():
    leaves = [BookmarkNode(title=f"L{i}", kind="bookmark", url=f"https://x/{i}") for i in range(5)]
    folder = BookmarkNode(title="Folder", kind="folder", children=leaves)
    payload = build_chrome_bookmarks([SpaceTree(name="S", profile_dir="Default", pinned=[folder])])

    ids: list[str] = []

    def collect(node: dict) -> None:
        if "id" in node:
            ids.append(node["id"])
        for c in node.get("children", []) or []:
            collect(c)

    for root in payload["roots"].values():
        collect(root)

    assert len(ids) == len(set(ids)), f"duplicate ids: {ids}"
