"""Chrome ``Bookmarks`` JSON writer covers Arc *favorites only*.

Pinned tabs / today-tabs are opened as actual Chrome tabs by the
tab-bootstrap extension; they intentionally do not appear here. Tests for
that path live in ``test_tabs_bootstrap.py`` and ``test_targets.py``.
"""

from __future__ import annotations

import json
from pathlib import Path

from arc_exporter.export.bookmarks_chrome_json import (
    build_chrome_bookmarks,
    write_chrome_bookmarks,
)
from arc_exporter.parsers.sidebar import BookmarkNode, SpaceTree


def _space_with_favorites() -> SpaceTree:
    favs = [
        BookmarkNode(title="Gmail", kind="bookmark", url="https://mail.google.com/"),
        BookmarkNode(title="Calendar", kind="bookmark", url="https://calendar.google.com/"),
    ]
    pinned_leaf = BookmarkNode(title="DontShow", kind="bookmark", url="https://x.test/")
    today_leaf = BookmarkNode(title="DontShowEither", kind="bookmark", url="https://y.test/")
    return SpaceTree(
        name="Work",
        profile_dir="Default",
        favorites=favs,
        pinned=[pinned_leaf],
        today_tabs=[today_leaf],
    )


def test_build_has_chrome_schema():
    payload = build_chrome_bookmarks([_space_with_favorites()])
    assert payload["version"] == 1
    roots = payload["roots"]
    assert set(roots) == {"bookmark_bar", "other", "synced"}
    bar = roots["bookmark_bar"]
    assert bar["type"] == "folder"
    assert bar["id"] == "1"
    # Two favorites land as flat children of the bookmark bar.
    children = bar["children"]
    assert len(children) == 2
    assert [c["name"] for c in children] == ["Gmail", "Calendar"]
    assert all(c["type"] == "url" for c in children)
    # The pinned + today-tab URLs MUST NOT appear in bookmarks.
    all_urls = {c.get("url") for c in children}
    assert "https://x.test/" not in all_urls
    assert "https://y.test/" not in all_urls


def test_space_without_favorites_writes_empty_bar():
    """A space with only pinned/today URLs (no favorites) leaves the bar empty —
    those URLs are restored as Chrome tabs instead of bookmarks."""
    only_pinned = SpaceTree(
        name="Tabs only",
        profile_dir="Default",
        pinned=[BookmarkNode(title="P", kind="bookmark", url="https://p.test/")],
        today_tabs=[BookmarkNode(title="T", kind="bookmark", url="https://t.test/")],
    )
    payload = build_chrome_bookmarks([only_pinned])
    assert payload["roots"]["bookmark_bar"]["children"] == []


def test_favorites_are_deduped_across_spaces():
    """Arc keeps a separate favorites container per profile and we have
    historical containers from old machines whose URLs overlap with the
    current ones. The writer must not duplicate them."""
    fav = BookmarkNode(title="Mail", kind="bookmark", url="https://mail.example/")
    a = SpaceTree(name="A", profile_dir="Default", favorites=[fav])
    b = SpaceTree(name="B", profile_dir="Default", favorites=[fav])
    payload = build_chrome_bookmarks([a, b])
    children = payload["roots"]["bookmark_bar"]["children"]
    assert len(children) == 1
    assert children[0]["url"] == "https://mail.example/"


def test_write_returns_favorite_count_and_strips_bak(tmp_path: Path):
    dest = tmp_path / "Bookmarks"
    bak = tmp_path / "Bookmarks.bak"
    bak.write_text("stale", encoding="utf-8")
    n = write_chrome_bookmarks([_space_with_favorites()], dest)
    assert n == 2  # two favorites
    assert dest.exists()
    assert not bak.exists()
    data = json.loads(dest.read_text())
    bar = data["roots"]["bookmark_bar"]["children"]
    assert {c["name"] for c in bar} == {"Gmail", "Calendar"}


def test_unique_ids_within_payload():
    favs = [BookmarkNode(title=f"L{i}", kind="bookmark", url=f"https://x/{i}") for i in range(5)]
    payload = build_chrome_bookmarks([SpaceTree(name="S", profile_dir="Default", favorites=favs)])

    ids: list[str] = []

    def collect(node: dict) -> None:
        if "id" in node:
            ids.append(node["id"])
        for c in node.get("children", []) or []:
            collect(c)

    for root in payload["roots"].values():
        collect(root)

    assert len(ids) == len(set(ids)), f"duplicate ids: {ids}"
