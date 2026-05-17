"""NETSCAPE bookmarks HTML writer with escaping, ``ADD_DATE`` and ``ICON``.

The output is the same format Chrome, Firefox, Safari, and Brave use for bookmark
import/export. Importantly we:

- HTML-escape every ``title`` and ``url`` so a malicious page title like
  ``</A><script>alert(1)</script>`` cannot inject script into the file.
- Emit ``ADD_DATE`` (POSIX seconds) on every leaf when known.
- Emit ``ICON="data:image/png;base64,..."`` when a favicon was supplied — most browsers
  preserve it on import.
"""

from __future__ import annotations

import html
from collections.abc import Iterable
from pathlib import Path

from arc_exporter.parsers.sidebar import BookmarkNode, SpaceTree
from arc_exporter.util import open_private

_HEADER = (
    "<!DOCTYPE NETSCAPE-Bookmark-file-1>\n"
    '<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">\n'
    "<TITLE>Bookmarks</TITLE>\n"
    "<H1>Bookmarks</H1>\n"
    "<DL><p>\n"
)
_FOOTER = "</DL><p>\n"


def render_tree_to_html(spaces: Iterable[SpaceTree], *, include_today_tabs: bool = True) -> str:
    """Render a sequence of :class:`SpaceTree` to a NETSCAPE bookmarks HTML string.

    Each space becomes a top-level folder containing (in order): a "Favorites"
    sub-folder mirroring Arc's icon strip, a "Today Tabs" sub-folder for open
    tabs, and then the pinned tree. Empty spaces are skipped entirely.
    """
    parts = [_HEADER]
    seen_favorites: set[str] = set()
    for space in spaces:
        space_children: list[BookmarkNode] = []
        # Favorites first (Arc shows them at the top of the sidebar). De-dupe
        # across spaces sharing the same profile so the user doesn't see the
        # same icon strip twice.
        unique_favs = [f for f in space.favorites if not (f.url and f.url in seen_favorites)]
        for f in unique_favs:
            if f.url:
                seen_favorites.add(f.url)
        if unique_favs:
            space_children.append(
                BookmarkNode(title="Favorites", kind="folder", children=unique_favs)
            )
        if include_today_tabs and space.today_tabs:
            space_children.append(
                BookmarkNode(title="Today Tabs", kind="folder", children=list(space.today_tabs))
            )
        space_children.extend(space.pinned)
        if not space_children:
            continue
        space_folder = BookmarkNode(title=space.name, kind="folder", children=space_children)
        parts.append(_render_node(space_folder, level=1))
    parts.append(_FOOTER)
    return "".join(parts)


def write_bookmarks_html(
    out_path: Path,
    spaces: Iterable[SpaceTree],
    *,
    include_today_tabs: bool = True,
) -> Path:
    """Render to ``out_path``; returns the path for chaining."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    content = render_tree_to_html(spaces, include_today_tabs=include_today_tabs)
    with open_private(out_path, "w") as f:
        f.write(content)
    return out_path


def _render_node(node: BookmarkNode, *, level: int) -> str:
    indent = "    " * level
    if node.kind == "folder":
        head = f"{indent}<DT><H3>{html.escape(node.title, quote=True)}</H3>\n"
        head += f"{indent}<DL><p>\n"
        body = "".join(_render_node(c, level=level + 1) for c in node.children)
        return head + body + f"{indent}</DL><p>\n"
    # bookmark
    attrs = [f'HREF="{html.escape(node.url or "", quote=True)}"']
    if node.add_date:
        attrs.append(f'ADD_DATE="{int(node.add_date)}"')
    if node.icon:
        attrs.append(f'ICON="{html.escape(node.icon, quote=True)}"')
    return f"{indent}<DT><A {' '.join(attrs)}>{html.escape(node.title, quote=True)}</A>\n"
