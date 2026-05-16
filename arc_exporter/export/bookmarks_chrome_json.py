"""Convert Arc sidebar trees into a Chrome-format ``Bookmarks`` JSON file.

The native bookmarks file Chrome reads on startup uses a strict JSON schema (one root
file per profile, three named roots: ``bookmark_bar``, ``other``, ``synced``). Without
this writer, the chromium full migration would copy Arc's empty per-profile
``Bookmarks`` file and the user would see an empty bookmark bar after import.

We populate ``bookmark_bar`` with one folder per Arc Space, preserving each space's
pinned tree of folders/leaves. Anything we can't classify lands under ``other``. The
``synced`` root is left empty — Chrome will fill it in once the user signs in.
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


def _wrap_space(space: SpaceTree, counter: list[int]) -> dict | None:
    children = [_convert_node(n, counter) for n in space.pinned]
    if not children:
        return None
    return {
        "children": children,
        "date_added": "0",
        "date_modified": "0",
        "guid": str(uuid.uuid4()),
        "id": _next_id(counter),
        "name": space.name or "Arc Space",
        "type": "folder",
    }


def build_chrome_bookmarks(spaces: Iterable[SpaceTree]) -> dict:
    """Produce a dict in the schema Chrome expects at ``Profile N/Bookmarks``."""
    counter = [3]  # ids 1, 2, 3 are reserved for the three roots
    bar_children: list[dict] = []
    other_children: list[dict] = []
    for sp in spaces:
        folder = _wrap_space(sp, counter)
        if folder is not None:
            bar_children.append(folder)
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

    Returns the count of top-level Space folders written under ``bookmark_bar``. The
    sibling ``Bookmarks.bak`` file is removed if present so Chrome regenerates a clean
    backup on next launch.
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
    return len(payload["roots"]["bookmark_bar"]["children"])
