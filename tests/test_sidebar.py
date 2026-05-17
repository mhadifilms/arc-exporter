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


def _sidebar_with_top_apps() -> dict:
    """Sidebar with one space + two top-apps (Favorites) containers.

    Mirrors Arc's real layout: ``topAppsContainerIDs`` lists pairs of
    ``[profile_descriptor, container_id]``, and each container is also a
    top-level item whose ``data.itemContainer.containerType.topApps._0``
    re-asserts its owning profile.
    """
    return {
        "sidebar": {
            "containers": [
                {"global": {}},
                {
                    "spaces": [
                        "S1",
                        {
                            "title": "Personal",
                            "profile": {"default": {}},
                            "newContainerIDs": [
                                {"pinned": {}}, "PIN1",
                                {"unpinned": {}}, "UNP1",
                            ],
                        },
                        "S2",
                        {
                            "title": "Work",
                            "profile": {"custom": {"_0": {"directoryBasename": "Profile 3"}}},
                            "newContainerIDs": [
                                {"pinned": {}}, "PIN2",
                                {"unpinned": {}}, "UNP2",
                            ],
                        },
                    ],
                    "topAppsContainerIDs": [
                        {"default": True}, "TOP-DEFAULT",
                        {"custom": {"_0": {"directoryBasename": "Profile 3"}}}, "TOP-P3",
                    ],
                    "items": [
                        "PIN1", {"childrenIds": []},
                        "UNP1", {"childrenIds": []},
                        "PIN2", {"childrenIds": []},
                        "UNP2", {"childrenIds": []},
                        "TOP-DEFAULT",
                        {
                            "childrenIds": ["FAV-1", "FAV-2"],
                            "data": {
                                "itemContainer": {
                                    "containerType": {"topApps": {"_0": {"default": True}}}
                                }
                            },
                        },
                        "FAV-1",
                        {"data": {"tab": {"savedTitle": "Gmail", "savedURL": "https://mail.google.com/"}}},
                        "FAV-2",
                        {"data": {"tab": {"savedTitle": "Cal", "savedURL": "https://calendar.google.com/"}}},
                        "TOP-P3",
                        {
                            "childrenIds": ["FAV-3"],
                            "data": {
                                "itemContainer": {
                                    "containerType": {
                                        "topApps": {"_0": {"custom": {"_0": {"directoryBasename": "Profile 3"}}}}
                                    }
                                }
                            },
                        },
                        "FAV-3",
                        {"data": {"tab": {"savedTitle": "Slack", "savedURL": "https://app.slack.com/"}}},
                    ],
                },
            ]
        }
    }


def test_favorites_attached_per_profile():
    """``topApps`` containers should be split by owning profile, even when no
    profile-specific space exists, and de-duplicated by URL."""
    result = parse_sidebar(_sidebar_with_top_apps())
    by_profile = {s.profile_dir: s for s in result.spaces}
    assert sorted(by_profile.keys()) == ["Default", "Profile 3"]

    default_favs = [f.url for f in by_profile["Default"].favorites]
    assert default_favs == ["https://mail.google.com/", "https://calendar.google.com/"]
    p3_favs = [f.url for f in by_profile["Profile 3"].favorites]
    assert p3_favs == ["https://app.slack.com/"]


def test_total_urls_counts_favorites_pinned_and_today():
    """``SpaceTree.total_urls`` should sum every leaf across the three buckets."""
    result = parse_sidebar(_sidebar_with_top_apps())
    by_profile = {s.profile_dir: s for s in result.spaces}
    # Default profile: 0 pinned + 0 today + 2 favorites
    assert by_profile["Default"].total_urls() == 2
    # Profile 3: 0 pinned + 0 today + 1 favorite
    assert by_profile["Profile 3"].total_urls() == 1


def test_chrome_bookmarks_favorites_are_flat_urls():
    """Favorites are the only thing that lands in the bookmark bar. We deliberately
    flatten them — no space folder wrapper — so they mirror Arc's icon strip
    instead of being hidden behind a "Work" folder. Pinned + today-tabs are
    handled by the tab-bootstrap extension and must not appear here."""
    from arc_exporter.export.bookmarks_chrome_json import build_chrome_bookmarks

    result = parse_sidebar(_sidebar_with_top_apps())
    payload = build_chrome_bookmarks(result.for_profile("Default"))
    bar = payload["roots"]["bookmark_bar"]["children"]
    urls = [c["url"] for c in bar if c["type"] == "url"]
    assert urls == ["https://mail.google.com/", "https://calendar.google.com/"]


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
