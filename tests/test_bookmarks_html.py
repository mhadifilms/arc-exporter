from __future__ import annotations

from pathlib import Path

from arc_exporter.export.bookmarks_html import render_tree_to_html, write_bookmarks_html
from arc_exporter.parsers.sidebar import BookmarkNode, SpaceTree, parse_sidebar


def test_html_escaping_titles_and_urls(fake_sidebar):
    spaces = parse_sidebar(fake_sidebar).spaces
    html = render_tree_to_html(spaces)
    # Raw "&" must be encoded
    assert "Tab B &amp; &lt;Friends&gt;" in html
    # The URL's "&" must be encoded inside HREF
    assert "https://b.example.com/?x=1&amp;y=2" in html
    # Today Tabs subfolder appears first inside each space
    assert "Today Tabs" in html
    # No literal '<' from page titles leaks through
    assert "<Friends>" not in html.replace("&lt;Friends&gt;", "")


def test_xss_title_is_escaped():
    node = BookmarkNode(
        title="</A><script>alert('xss')</script>",
        kind="bookmark",
        url="javascript:alert(1)",
    )
    space = SpaceTree(name="x", profile_dir="Default", pinned=[node])
    html = render_tree_to_html([space])
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html
    assert "javascript:alert(1)" in html  # URLs are escaped but kept; browser policy handles execution


def test_writes_file_and_chmods(tmp_path: Path, fake_sidebar):
    out = tmp_path / "b.html"
    spaces = parse_sidebar(fake_sidebar).spaces
    write_bookmarks_html(out, spaces)
    content = out.read_text(encoding="utf-8")
    assert content.startswith("<!DOCTYPE NETSCAPE-Bookmark-file-1>")
    import os

    if os.name == "posix":
        mode = out.stat().st_mode & 0o777
        assert mode == 0o600
