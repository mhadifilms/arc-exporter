"""Convert Arc sidebar trees into a Chrome-format ``Bookmarks`` JSON file.

The native bookmarks file Chrome reads on startup uses a strict JSON schema (one
root file per profile, three named roots: ``bookmark_bar``, ``other``, ``synced``).

Scope (matches Arc's mental model — *not* a dump of every URL):
- **Arc Favorites** (the icon strip at the top of each space) -> Chrome bookmark
  bar. Mirrors what users actually treat as bookmarks in Arc.
- **Arc Pinned tabs** and **Today tabs** -> NOT bookmarks. Those are opened as
  actual Chrome tabs by the bootstrap extension in ``targets/tabs_bootstrap``.
  Pinned-folder structure is converted to Chrome tab groups; pinned leaves
  become pinned tabs; today tabs become open tabs.

Why we don't put pinned tabs in bookmarks anymore: Arc users expect their
pinned tabs to remain *tabs*, not buried in a bookmark folder. Dropping them
into ``bookmark_bar`` made every migration look right on paper but felt wrong
in practice — the bookmark bar got cluttered while Chrome opened to an empty
NTP every launch.
"""

from __future__ import annotations

import json
import os
import uuid
from collections.abc import Iterable
from pathlib import Path

from arc_exporter.parsers.sidebar import BookmarkNode, SpaceTree
from arc_exporter.util import chmod_private

_CHROMIUM_EPOCH_OFFSET_US = 11_644_473_600_000_000  # microseconds between 1601-01-01 and 1970-01-01


def _unix_to_chromium_us(unix_seconds: int | float | None) -> str:
    """Convert a unix epoch (seconds) to Chromium microseconds-since-1601 as a string."""
    if unix_seconds is None:
        return "0"
    return str(int(unix_seconds * 1_000_000) + _CHROMIUM_EPOCH_OFFSET_US)


def _next_id(counter: list[int]) -> str:
    counter[0] += 1
    return str(counter[0])


def _convert_node(node: BookmarkNode, counter: list[int]) -> dict:
    item_id = _next_id(counter)
    base: dict = {
        "date_added": _unix_to_chromium_us(node.add_date),
        "guid": str(uuid.uuid4()),
        "id": item_id,
        "name": node.title or "",
    }
    if node.kind == "folder":
        base["children"] = [_convert_node(c, counter) for c in node.children]
        base["date_modified"] = _unix_to_chromium_us(node.add_date)
        base["type"] = "folder"
    else:
        base["type"] = "url"
        base["url"] = node.url or ""
    return base


def _favorites_for_space(space: SpaceTree, counter: list[int], seen_favorites: set[str]) -> list[dict]:
    """Return the favorite leaves for one space as Chrome bookmark nodes.

    De-duplicates by URL across spaces because Arc keeps a separate favorites
    container per profile (and our user has historical containers from old
    machines that still resolve to the same URLs). Without this, a profile
    with multiple spaces would see the same icon repeated.
    """
    out: list[dict] = []
    for fav in space.favorites:
        if fav.url and fav.url in seen_favorites:
            continue
        if fav.url:
            seen_favorites.add(fav.url)
        out.append(_convert_node(fav, counter))
    return out


def build_chrome_bookmarks(spaces: Iterable[SpaceTree]) -> dict:
    """Produce a dict in the schema Chrome expects at ``Profile N/Bookmarks``.

    Only Arc Favorites are written. Pinned tabs and today-tabs are intentionally
    omitted — they're opened as actual Chrome tabs by the tab bootstrap
    extension. The bookmark bar ends up flat (favicons-as-rows), exactly like
    Arc's icon strip across the top of each space.
    """
    counter = [3]  # ids 1, 2, 3 are reserved for the three roots
    bar_children: list[dict] = []
    other_children: list[dict] = []
    seen_favorites: set[str] = set()
    for sp in spaces:
        bar_children.extend(_favorites_for_space(sp, counter, seen_favorites))
    return {
        "checksum": "",  # Chrome recomputes on read
        "roots": {
            "bookmark_bar": {
                "children": bar_children,
                "date_added": "0",
                "date_modified": "0",
                "guid": "0bc5d13f-2cba-5d74-951f-3f233fe6c908",
                "id": "1",
                "name": "Bookmarks bar",
                "type": "folder",
            },
            "other": {
                "children": other_children,
                "date_added": "0",
                "date_modified": "0",
                "guid": "82b081ec-3dd3-529c-8475-ab6c344590dd",
                "id": "2",
                "name": "Other bookmarks",
                "type": "folder",
            },
            "synced": {
                "children": [],
                "date_added": "0",
                "date_modified": "0",
                "guid": "323123f4-9381-5aee-80e6-ea5fca2f7672",
                "id": "3",
                "name": "Mobile bookmarks",
                "type": "folder",
            },
        },
        "version": 1,
    }


def write_chrome_bookmarks(spaces: Iterable[SpaceTree], dest: Path) -> int:
    """Write the converted bookmarks JSON to ``dest``.

    Returns the number of favorite URLs written to the bookmark bar — exactly
    what shows up to the user as bookmarks in the new Chrome profile.

    The sibling ``Bookmarks.bak`` file is removed if present so Chrome
    regenerates a clean backup on next launch.
    """
    payload = build_chrome_bookmarks(spaces)
    dest.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=3)  # Chrome itself uses 3-space indent
    dest.write_text(text, encoding="utf-8")
    chmod_private(dest)
    bak = dest.with_suffix(dest.suffix + ".bak") if dest.suffix else dest.parent / (dest.name + ".bak")
    bak_alt = dest.parent / (dest.name + ".bak")
    for candidate in {bak, bak_alt}:
        try:
            os.remove(candidate)
        except FileNotFoundError:
            pass
        except OSError:
            pass
    return _count_url_leaves(payload["roots"]["bookmark_bar"])


def _count_url_leaves(node: dict) -> int:
    if node.get("type") == "url":
        return 1
    return sum(_count_url_leaves(c) for c in node.get("children", []))
