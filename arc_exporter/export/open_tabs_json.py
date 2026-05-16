"""Write currently-open tabs as JSON suitable for OneTab / Toby / TabBoard imports."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from arc_exporter.parsers.sidebar import SpaceTree, flatten_urls
from arc_exporter.util import open_private


def write_open_tabs_json(out_path: Path, spaces: Iterable[SpaceTree]) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload: list[dict] = []
    n = 0
    for space in spaces:
        urls = []
        for title, url in flatten_urls(space.today_tabs):
            urls.append({"title": title, "url": url})
            n += 1
        payload.append({"space": space.name, "tabs": urls})
    with open_private(out_path, "w") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    return n
