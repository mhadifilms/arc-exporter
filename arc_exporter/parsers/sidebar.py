"""Parse Arc's ``StorableSidebar.json`` into a typed, cycle-safe tree.

Arc stores the sidebar as a flat list of items keyed by a pair-encoded ``[id, data, id,
data, ...]`` array. Each item may be a tab, a folder, a tab group (subfolder), a split
view, or a space. The legacy code walked this structure recursively without cycle
detection — a malformed file could trigger unbounded recursion. This module fixes that
and adds a stable, testable type model.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from arc_exporter.errors import CorruptDataError


@dataclass
class BookmarkNode:
    """A folder or leaf bookmark."""

    title: str
    kind: Literal["bookmark", "folder"]
    url: str | None = None
    add_date: int | None = None
    icon: str | None = None  # data: URI for embedded favicon, optional
    children: list[BookmarkNode] = field(default_factory=list)


@dataclass
class SpaceTree:
    name: str
    profile_dir: str
    pinned: list[BookmarkNode] = field(default_factory=list)
    today_tabs: list[BookmarkNode] = field(default_factory=list)
    favorites: list[BookmarkNode] = field(default_factory=list)
    """Arc's "Favorites" row (the icon strip at the top of the sidebar). Stored
    per-profile in ``StorableSidebar.json`` under ``topAppsContainerIDs``. We
    attach them to every space owned by the profile; renderers should
    de-duplicate as needed."""

    def total_urls(self) -> int:
        return _count_urls(self.favorites) + _count_urls(self.pinned) + _count_urls(self.today_tabs)


@dataclass
class SidebarParseResult:
    spaces: list[SpaceTree]
    profile_to_spaces: dict[str, list[str]]

    def for_profile(self, profile_dir: str) -> list[SpaceTree]:
        return [s for s in self.spaces if s.profile_dir == profile_dir]


def _count_urls(nodes: Iterable[BookmarkNode]) -> int:
    """Walk ``nodes`` recursively and count every leaf bookmark with a URL."""
    stack = list(nodes)
    n = 0
    while stack:
        node = stack.pop()
        if node.kind == "bookmark" and node.url:
            n += 1
        else:
            stack.extend(node.children)
    return n


def load_sidebar(path: Path) -> SidebarParseResult:
    """Parse the sidebar file at ``path``. Returns an empty result if the file is missing."""
    if not path.exists():
        return SidebarParseResult(spaces=[], profile_to_spaces={})
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise CorruptDataError(f"could not read sidebar JSON: {e}") from e
    return parse_sidebar(data)


def parse_sidebar(data: dict) -> SidebarParseResult:
    """Pure-data variant of :func:`load_sidebar` for tests and fixtures."""
    containers = (data.get("sidebar") or {}).get("containers") or []
    if not containers:
        return SidebarParseResult(spaces=[], profile_to_spaces={})

    main = _find_main_container(containers)
    if main is None:
        return SidebarParseResult(spaces=[], profile_to_spaces={})

    profile_to_spaces = _profile_to_spaces_from(main.get("spaces") or [])

    item_index = _index_items(main.get("items") or [])
    spaces_meta = _spaces_meta(main.get("spaces") or [])

    pinned_by_space, unpinned_by_space, space_to_profile = _classify_containers(main.get("spaces") or [])

    # Favorites (Arc's "topApps" — the icon row at the top of the sidebar)
    # are stored as their own root-level itemContainers, one per profile.
    # We pull them out of the global item index so we can attach them to each
    # profile's spaces below.
    favorites_by_profile = _extract_favorites(item_index)

    spaces: list[SpaceTree] = []
    for container_id, space_name in pinned_by_space.items():
        pinned = _walk_children(container_id, item_index)
        today_container = _find_unpinned_for_space(space_name, unpinned_by_space)
        today_tabs: list[BookmarkNode] = []
        if today_container:
            today_tabs = _walk_children(today_container, item_index, only_tabs=True)
        profile_dir = space_to_profile.get(space_name, "Default")
        spaces.append(
            SpaceTree(
                name=space_name,
                profile_dir=profile_dir,
                pinned=pinned,
                today_tabs=today_tabs,
                favorites=list(favorites_by_profile.get(profile_dir, [])),
            )
        )
    # Preserve sidebar order
    spaces.sort(
        key=lambda s: (
            list(pinned_by_space.values()).index(s.name) if s.name in pinned_by_space.values() else 0
        )
    )
    _ = spaces_meta  # reserved for future metadata
    return SidebarParseResult(spaces=spaces, profile_to_spaces=profile_to_spaces)


def _find_main_container(containers: list) -> dict | None:
    """Find the container holding ``spaces`` and ``items``.

    Arc 0.x lays containers out as ``[marker_dict_with_global_key, data_dict, ...]``
    where the marker dict has only ``{"global": {}}`` and the data dict has ``spaces``
    and ``items``. We prefer a dict that actually carries data; fall back to the dict
    immediately after a ``global`` marker for compatibility with older formats.
    """
    for c in containers:
        if isinstance(c, dict) and ("spaces" in c or "items" in c):
            return c
    for i, c in enumerate(containers):
        if isinstance(c, dict) and "global" in c and i + 1 < len(containers):
            nxt = containers[i + 1]
            if isinstance(nxt, dict):
                return nxt
    return None


def _index_items(items: list) -> dict[str, dict]:
    index: dict[str, dict] = {}
    for i in range(0, len(items), 2):
        if i + 1 >= len(items):
            break
        key, val = items[i], items[i + 1]
        if isinstance(val, dict):
            index[key] = val
    return index


def _spaces_meta(spaces: list) -> dict[str, dict]:
    meta: dict[str, dict] = {}
    for i in range(0, len(spaces), 2):
        if i + 1 >= len(spaces):
            break
        sid, sdata = spaces[i], spaces[i + 1]
        if isinstance(sdata, dict):
            meta[str(sid)] = sdata
    return meta


def _profile_to_spaces_from(spaces_list: list) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for i in range(0, len(spaces_list), 2):
        if i + 1 >= len(spaces_list):
            break
        sdata = spaces_list[i + 1]
        if not isinstance(sdata, dict):
            continue
        title = sdata.get("title")
        if not title:
            continue
        profile_info = sdata.get("profile") or {}
        profile_dir = "Default"
        if "custom" in profile_info:
            custom = profile_info["custom"]
            if isinstance(custom, dict) and "_0" in custom:
                profile_dir = custom["_0"].get("directoryBasename", "Default")
        out.setdefault(profile_dir, []).append(title)
    return out


def _classify_containers(spaces: list) -> tuple[dict[str, str], dict[str, str], dict[str, str]]:
    """Return ``(pinned[container_id]=space_name, unpinned[container_id]=space_name, space_name->profile_dir)``."""
    pinned: dict[str, str] = {}
    unpinned: dict[str, str] = {}
    space_to_profile: dict[str, str] = {}
    n = 1
    for i in range(0, len(spaces), 2):
        if i + 1 >= len(spaces):
            break
        sdata = spaces[i + 1]
        if not isinstance(sdata, dict):
            continue
        title = sdata.get("title") or f"Space {n}"
        n += 1
        profile_dir = "Default"
        profile_info = sdata.get("profile") or {}
        if "custom" in profile_info:
            custom = profile_info["custom"]
            if isinstance(custom, dict) and "_0" in custom:
                profile_dir = custom["_0"].get("directoryBasename", "Default")
        space_to_profile[title] = profile_dir
        new_containers = sdata.get("newContainerIDs") or []
        for j, marker in enumerate(new_containers):
            if not isinstance(marker, dict) or j + 1 >= len(new_containers):
                continue
            cid = str(new_containers[j + 1])
            if "pinned" in marker:
                pinned[cid] = title
            elif "unpinned" in marker:
                unpinned[cid] = title
    return pinned, unpinned, space_to_profile


def _find_unpinned_for_space(space_name: str, unpinned: dict[str, str]) -> str | None:
    for cid, name in unpinned.items():
        if name == space_name:
            return cid
    return None


def _extract_favorites(item_index: dict[str, dict]) -> dict[str, list[BookmarkNode]]:
    """Walk every ``topApps`` container in ``item_index`` and group its tabs by
    the profile that owns them.

    Each ``topApps`` container is its own root-level item whose
    ``data.itemContainer.containerType.topApps._0`` payload describes the
    owning profile in one of two shapes:

    - ``{"default": True}`` — the Arc ``Default`` profile.
    - ``{"custom": {"_0": {"directoryBasename": "Profile 7", "machineID": …}}}``
      — a custom profile, keyed by its on-disk directory name.

    A given profile can have multiple ``topApps`` containers (Arc syncs the
    icon row across machines, so each ``machineID`` ends up with its own
    container). We merge them per ``directoryBasename`` and de-duplicate by
    URL so the user doesn't see the same favorite twice.
    """
    out: dict[str, list[BookmarkNode]] = {}
    seen_urls_by_profile: dict[str, set[str]] = {}
    for item_id, node in item_index.items():
        data = node.get("data") or {}
        container = data.get("itemContainer") or {}
        ctype = container.get("containerType") or {}
        top_apps = ctype.get("topApps") if isinstance(ctype, dict) else None
        if not isinstance(top_apps, dict):
            continue
        owner = top_apps.get("_0")
        profile_dir = _profile_dir_from_owner(owner)
        if not profile_dir:
            continue
        children = _walk_children(item_id, item_index, only_tabs=True)
        if not children:
            continue
        seen = seen_urls_by_profile.setdefault(profile_dir, set())
        favorites = out.setdefault(profile_dir, [])
        for node_url in _flatten_unique(children, seen):
            favorites.append(node_url)
    return out


def _profile_dir_from_owner(owner: object) -> str | None:
    if not isinstance(owner, dict):
        return None
    if owner.get("default") is True:
        return "Default"
    custom = owner.get("custom")
    if isinstance(custom, dict):
        inner = custom.get("_0")
        if isinstance(inner, dict):
            d = inner.get("directoryBasename")
            if isinstance(d, str) and d:
                return d
    return None


def _flatten_unique(nodes: Iterable[BookmarkNode], seen: set[str]) -> Iterable[BookmarkNode]:
    """Yield ``BookmarkNode`` instances skipping URLs we've already emitted.

    Folders are descended into; their leaves are emitted directly (we
    flatten favorites so the user gets a single tidy icon row in the
    bookmark bar, not a nested mess).
    """
    stack: list[BookmarkNode] = list(nodes)
    while stack:
        node = stack.pop(0)
        if node.kind == "bookmark" and node.url:
            if node.url in seen:
                continue
            seen.add(node.url)
            yield node
        else:
            stack[:0] = node.children


def _walk_children(root_id: str, items: dict[str, dict], *, only_tabs: bool = False) -> list[BookmarkNode]:
    visited: set[str] = set()

    def recurse(node_id: str, depth: int = 0) -> list[BookmarkNode]:
        if depth > 256 or node_id in visited:
            return []
        visited.add(node_id)
        node = items.get(node_id)
        if not node:
            return []
        out: list[BookmarkNode] = []
        for child_id in node.get("childrenIds") or []:
            child = items.get(child_id)
            if not child:
                continue
            data = child.get("data") or {}
            if "tab" in data:
                tab = data["tab"] or {}
                title = (child.get("title") or tab.get("savedTitle") or tab.get("title") or "").strip()
                url = tab.get("savedURL") or tab.get("url")
                if title and url:
                    out.append(BookmarkNode(title=title, kind="bookmark", url=url))
                continue
            if "splitView" in data:
                for sv_child_id in child.get("childrenIds") or []:
                    sv_child = items.get(sv_child_id)
                    if not sv_child:
                        continue
                    sv_data = sv_child.get("data") or {}
                    if "tab" not in sv_data:
                        continue
                    tab = sv_data["tab"] or {}
                    title = (sv_child.get("title") or tab.get("savedTitle") or "").strip()
                    url = tab.get("savedURL") or tab.get("url")
                    if title and url:
                        out.append(BookmarkNode(title=title, kind="bookmark", url=url))
                continue
            if "tabGroup" in data:
                if only_tabs:
                    grand = recurse(child_id, depth + 1)
                    folder_title = (data["tabGroup"].get("title") or child.get("title") or "Folder").strip()
                    if grand:
                        out.append(BookmarkNode(title=folder_title, kind="folder", children=grand))
                else:
                    grand = recurse(child_id, depth + 1)
                    folder_title = (data["tabGroup"].get("title") or child.get("title") or "Folder").strip()
                    if grand:
                        out.append(BookmarkNode(title=folder_title, kind="folder", children=grand))
                continue
            # Plain folder node
            title = (child.get("title") or "").strip()
            if not title:
                continue
            grand = recurse(child_id, depth + 1)
            if grand:
                out.append(BookmarkNode(title=title, kind="folder", children=grand))
        return out

    return recurse(root_id)


def flatten_urls(nodes: Iterable[BookmarkNode]) -> Iterable[tuple[str, str]]:
    """Yield ``(title, url)`` for every leaf in a list of trees (depth-first)."""
    stack = list(nodes)
    while stack:
        node = stack.pop()
        if node.kind == "bookmark" and node.url:
            yield node.title, node.url
        else:
            stack.extend(reversed(node.children))
