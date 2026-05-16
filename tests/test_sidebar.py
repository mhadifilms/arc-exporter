from __future__ import annotations

from arc_exporter.parsers.sidebar import flatten_urls, parse_sidebar


def test_parse_basic_structure(fake_sidebar):
    result = parse_sidebar(fake_sidebar)
    assert len(result.spaces) == 1
    space = result.spaces[0]
    assert space.name == "Personal"
    assert space.profile_dir == "Default"


def test_pinned_includes_folder_children(fake_sidebar):
    result = parse_sidebar(fake_sidebar)
    space = result.spaces[0]
    titles = {n.title for n in space.pinned}
    assert "Tab A" in titles
    assert "Work" in titles
    work = next(n for n in space.pinned if n.title == "Work")
    assert work.kind == "folder"
    assert work.children[0].title == "Tab B & <Friends>"


def test_today_tabs_include_splitview_children(fake_sidebar):
    result = parse_sidebar(fake_sidebar)
    space = result.spaces[0]
    urls = [n.url for n in space.today_tabs if n.kind == "bookmark"]
    assert "https://c.example.com/" in urls
    assert "https://left.example.com/" in urls
    assert "https://right.example.com/" in urls


def test_dangling_tabs_dropped(fake_sidebar):
    result = parse_sidebar(fake_sidebar)
    flat = list(flatten_urls(result.spaces[0].pinned + result.spaces[0].today_tabs))
    titles = [t for t, _ in flat]
    assert "Dangling" not in titles


def test_cycle_detection_does_not_recurse_forever():
    # Two nodes that reference each other; should not crash.
    data = {
        "sidebar": {
            "containers": [
                {"global": {}},
                {
                    "global": {},
                    "spaces": [
                        "S",
                        {
                            "title": "Loop",
                            "profile": {"default": {}},
                            "newContainerIDs": [{"pinned": {}}, "P"],
                        },
                    ],
                    "items": ["P", {"childrenIds": ["A"]}, "A", {"title": "A", "childrenIds": ["P"]}],
                },
            ]
        }
    }
    result = parse_sidebar(data)
    assert result.spaces[0].name == "Loop"
