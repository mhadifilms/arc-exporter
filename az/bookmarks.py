from pathlib import Path
from .paths import ARC_SIDEBAR, ARC_LOCAL_STATE
from .utils import ensure, read_json

def _arc_display_names() -> dict[str, str]:
    """Get mapping from profile directory name to display name."""
    ls = read_json(ARC_LOCAL_STATE)
    ic = (ls.get("profile") or {}).get("info_cache") or {}
    out = {}
    for k, meta in ic.items():
        nm = meta.get("name") if isinstance(meta, dict) else None
        out[k] = nm or k
    return out

def _build_profile_to_spaces_mapping(data: dict) -> dict[str, list[str]]:
    """
    Build a mapping from profile names to their associated space names.

    Arc stores spaces in the sidebar data, and each space has profile information
    that indicates whether it belongs to the default profile or a custom profile.

    Returns:
        dict mapping profile names (e.g., "Default", "Profile 1") to lists of space names
    """
    profile_to_spaces = {}

    # Navigate to the spaces in the sidebar data
    containers = data.get("sidebar", {}).get("containers", [])
    if len(containers) < 2:
        return profile_to_spaces

    spaces = containers[1].get("spaces", [])

    # Process spaces (they come in pairs: ID, space_data)
    for i in range(0, len(spaces), 2):
        if i + 1 >= len(spaces):
            break

        space_data = spaces[i + 1]
        if not isinstance(space_data, dict):
            continue

        space_title = space_data.get("title")
        profile_info = space_data.get("profile", {})

        if not space_title:
            continue

        # Determine profile name based on profile info
        profile_name = "Default"  # Default profile
        if "custom" in profile_info:
            custom_profile = profile_info["custom"]
            if isinstance(custom_profile, dict) and "_0" in custom_profile:
                profile_name = custom_profile["_0"].get("directoryBasename", "Default")

        # Add space to profile mapping
        if profile_name not in profile_to_spaces:
            profile_to_spaces[profile_name] = []
        profile_to_spaces[profile_name].append(space_title)

    return profile_to_spaces

def export_pinned_bookmarks(out_html: Path, space_title: str | None = None):
    """
    Export Arc bookmarks to HTML format.

    This function automatically detects the profile-to-space mapping from Arc's sidebar data
    and exports bookmarks accordingly. It fixes two main issues:

    1. No longer requires manual editing of profile_to_space_mapping
    2. Properly exports multiple spaces per profile instead of only the last one

    Args:
        out_html: Output path for the HTML bookmarks file
        space_title: Can be a profile display name (e.g., "Achilles"), profile name (e.g., "Profile 1"),
                    or specific space name (e.g., "Private"). If None, exports all spaces.
    """
    ensure(out_html.parent)
    data = read_json(ARC_SIDEBAR)

    # Automatically build profile-to-spaces mapping from the sidebar data
    profile_to_spaces = _build_profile_to_spaces_mapping(data)

    # Get the display name mapping from Arc's profile system
    arc_display_names = _arc_display_names()

    # Create a reverse mapping from display names to sidebar profile names
    display_to_sidebar_profile = {}
    for sidebar_profile, spaces in profile_to_spaces.items():
        # For "Default" profile, it maps directly
        if sidebar_profile == "Default":
            # Find all Arc profiles that map to "Default" display name
            for arc_profile_dir, display_name in arc_display_names.items():
                if arc_profile_dir == "Default" or display_name == "Default":
                    display_to_sidebar_profile[display_name] = sidebar_profile
        else:
            # For custom profiles like "Profile 1", find matching Arc profiles
            for arc_profile_dir, display_name in arc_display_names.items():
                if sidebar_profile.startswith("Profile") and arc_profile_dir.startswith("Profile"):
                    # Extract number from both to match
                    sidebar_num = sidebar_profile.replace("Profile ", "")
                    arc_num = arc_profile_dir.replace("Profile ", "")
                    if sidebar_num == arc_num:
                        display_to_sidebar_profile[display_name] = sidebar_profile

    # If space_title is provided, use it as a profile name and export all spaces for that profile
    spaces_to_export = []
    if space_title:
        # Try different mapping strategies
        if space_title in display_to_sidebar_profile:
            # Display name -> sidebar profile -> spaces
            sidebar_profile = display_to_sidebar_profile[space_title]
            spaces_to_export = profile_to_spaces[sidebar_profile]
        elif space_title in profile_to_spaces:
            # Direct sidebar profile name
            spaces_to_export = profile_to_spaces[space_title]
        else:
            # Treat as a specific space name
            spaces_to_export = [space_title]
    else:
        # Export all spaces from all profiles
        for spaces_list in profile_to_spaces.values():
            spaces_to_export.extend(spaces_list)

    html = _convert_json_to_html_legacy(data, spaces_to_export)
    with out_html.open("w", encoding="utf-8") as f:
        f.write(html)

def _extract_today_tabs_by_space(json_data: dict, spaces: dict) -> dict:
    """
    Extract currently opened tabs organized by space.
    Only includes unpinned tabs (open tabs), not pinned bookmarks.
    Handles both individual tabs and tabGroups (subfolders).

    Args:
        json_data: The StorableSidebar.json data
        spaces: The spaces dictionary from _get_spaces_legacy()

    Returns:
        dict mapping space names to lists of today's tabs for that space
    """
    tabs_by_space = {}
    containers = json_data.get("sidebar", {}).get("containers", [])

    if len(containers) < 2:
        return tabs_by_space

    # Get the main container that holds all items
    main_container = containers[1]
    if not isinstance(main_container, dict) or "items" not in main_container:
        return tabs_by_space

    items_list = main_container["items"]

    # Build item dictionary for fast lookup
    item_dict = {}
    for i in range(0, len(items_list), 2):
        if i + 1 >= len(items_list):
            break
        item_id = items_list[i]
        item_data = items_list[i + 1]
        if isinstance(item_data, dict):
            item_dict[item_id] = item_data

    # Helper function to recursively extract tabs from containers and tabGroups
    def extract_tabs_from_container(container_id: str, space_name: str) -> list:
        """Extract tabs from a container, handling both individual tabs and tabGroups."""
        result = []

        if container_id not in item_dict:
            return result

        container_item = item_dict[container_id]
        children_ids = container_item.get("childrenIds", [])

        for child_id in children_ids:
            if child_id not in item_dict:
                continue

            child_item = item_dict[child_id]

            if "data" not in child_item:
                continue

            child_data = child_item["data"]

            # Handle individual tabs
            if "tab" in child_data:
                tab = child_data["tab"]
                saved_title = tab.get("savedTitle", "")
                saved_url = tab.get("savedURL", "")

                if saved_title and saved_url:
                    result.append({
                        "title": saved_title,
                        "type": "bookmark",
                        "url": saved_url,
                    })

            # Handle top-level splitView items (which contain tabs as children)
            elif "splitView" in child_data:
                splitview_children_ids = child_item.get("childrenIds", [])
                for splitview_child_id in splitview_children_ids:
                    if splitview_child_id not in item_dict:
                        continue

                    splitview_child = item_dict[splitview_child_id]
                    if "data" in splitview_child and "tab" in splitview_child["data"]:
                        tab = splitview_child["data"]["tab"]
                        saved_title = tab.get("savedTitle", "")
                        saved_url = tab.get("savedURL", "")

                        if saved_title and saved_url:
                            result.append({
                                "title": saved_title,
                                "type": "bookmark",
                                "url": saved_url,
                            })

            # Handle tabGroups (subfolders)
            elif "tabGroup" in child_data:
                tabgroup = child_data["tabGroup"]
                folder_title = tabgroup.get("title", child_item.get("title", "Unnamed Folder"))

                # Recursively extract tabs from the tabGroup
                folder_tabs = []
                tabgroup_children_ids = child_item.get("childrenIds", [])

                for tab_id in tabgroup_children_ids:
                    if tab_id not in item_dict:
                        continue

                    tab_item = item_dict[tab_id]

                    # Handle direct tabs
                    if "data" in tab_item and "tab" in tab_item["data"]:
                        tab = tab_item["data"]["tab"]
                        saved_title = tab.get("savedTitle", "")
                        saved_url = tab.get("savedURL", "")

                        if saved_title and saved_url:
                            folder_tabs.append({
                                "title": saved_title,
                                "type": "bookmark",
                                "url": saved_url,
                            })

                    # Handle splitView items (which contain tabs as children)
                    elif "data" in tab_item and "splitView" in tab_item["data"]:
                        splitview_children_ids = tab_item.get("childrenIds", [])
                        for splitview_child_id in splitview_children_ids:
                            if splitview_child_id not in item_dict:
                                continue

                            splitview_child = item_dict[splitview_child_id]
                            if "data" in splitview_child and "tab" in splitview_child["data"]:
                                tab = splitview_child["data"]["tab"]
                                saved_title = tab.get("savedTitle", "")
                                saved_url = tab.get("savedURL", "")

                                if saved_title and saved_url:
                                    folder_tabs.append({
                                        "title": saved_title,
                                        "type": "bookmark",
                                        "url": saved_url,
                                    })

                # Add the folder with its tabs if it has any tabs
                if folder_tabs:
                    result.append({
                        "title": folder_title,
                        "type": "folder",
                        "children": folder_tabs,
                    })

        return result

    # Extract tabs for each space's unpinned container
    for container_id, space_name in spaces["unpinned"].items():
        space_tabs = extract_tabs_from_container(container_id, space_name)
        if space_tabs:
            tabs_by_space[space_name] = space_tabs

    return tabs_by_space

def _convert_json_to_html_legacy(json_data: dict, space_titles: list[str] | None = None) -> str:
    containers = json_data["sidebar"]["containers"]
    try:
        target = next(i + 1 for i, c in enumerate(containers) if "global" in c)
    except StopIteration:
        raise ValueError("No container with 'global' found in the sidebar data")

    spaces = _get_spaces_legacy(json_data["sidebar"]["containers"][target]["spaces"])
    items = json_data["sidebar"]["containers"][target]["items"]

    # Extract today's tabs organized by space
    tabs_by_space = _extract_today_tabs_by_space(json_data, spaces)

    bookmarks = _convert_to_bookmarks_legacy(spaces, items, space_titles, tabs_by_space)

    return _convert_bookmarks_to_html_legacy(bookmarks)

def _get_spaces_legacy(spaces: list) -> dict:
    spaces_names = {"pinned": {}, "unpinned": {}}
    n = 1
    for space in spaces:
        title = space["title"] if isinstance(space, dict) and "title" in space else f"Space {n}"; n += 1
        if isinstance(space, dict):
            containers = space.get("newContainerIDs", [])
            for i in range(len(containers)):
                if isinstance(containers[i], dict):
                    if "pinned" in containers[i] and i + 1 < len(containers):
                        spaces_names["pinned"][str(containers[i + 1])] = title
                    elif "unpinned" in containers[i] and i + 1 < len(containers):
                        spaces_names["unpinned"][str(containers[i + 1])] = title
    return spaces_names

def _convert_to_bookmarks_legacy(spaces: dict, items: list, space_titles: list[str] | None, tabs_by_space: dict) -> dict:
    bookmarks = {"bookmarks": []}

    # Create a dictionary for item lookup
    # Arc's items list structure is [id1, data1, id2, data2, ...]
    item_dict = {}
    for i in range(0, len(items), 2):
        if i + 1 >= len(items):
            break
        item_id = items[i]
        item_data = items[i + 1]
        if isinstance(item_data, dict):
            item_dict[item_id] = item_data

    # Get parent-child relationships while preserving order
    parent_child_map = {}
    for item_id, item in item_dict.items():
        if "childrenIds" in item and isinstance(item["childrenIds"], list):
            # Save children in the exact order they appear in childrenIds
            parent_child_map[item_id] = item["childrenIds"]

    def recurse_into_children(parent_id: str) -> list:
        children = []

        # Get the ordered list of children for this parent
        child_ids = parent_child_map.get(parent_id, [])

        for child_id in child_ids:
            if child_id not in item_dict:
                continue

            child_item = item_dict[child_id]

            # Handle bookmark/tab
            if "data" in child_item and "tab" in child_item["data"]:
                tab = child_item["data"]["tab"]
                title = child_item.get("title") or tab.get("savedTitle", "")
                url = tab.get("savedURL", "")

                if title and url:
                    children.append({
                        "title": title,
                        "type": "bookmark",
                        "url": url
                    })
            # Handle split view items (which contain tabs as children)
            elif "data" in child_item and "splitView" in child_item["data"]:
                # Process tabs within the split view
                splitview_children_ids = child_item.get("childrenIds", [])
                for splitview_child_id in splitview_children_ids:
                    if splitview_child_id not in item_dict:
                        continue

                    splitview_child = item_dict[splitview_child_id]
                    if "data" in splitview_child and "tab" in splitview_child["data"]:
                        tab = splitview_child["data"]["tab"]
                        title = splitview_child.get("title") or tab.get("savedTitle", "")
                        url = tab.get("savedURL", "")

                        if title and url:
                            children.append({
                                "title": title,
                                "type": "bookmark",
                                "url": url
                            })
            # Handle folders
            elif "title" in child_item:
                folder_title = child_item["title"]
                folder_children = recurse_into_children(child_id)

                if folder_title and folder_children:
                    children.append({
                        "title": folder_title,
                        "type": "folder",
                        "children": folder_children
                    })

        return children

    for space_id, space_name in spaces["pinned"].items():
        # If space_titles is None, export all spaces
        # If space_titles is provided, only export spaces that match
        if space_titles is not None and space_name not in space_titles:
            continue

        # Get the regular bookmarks for this space
        space_children = recurse_into_children(space_id)

        # Add "Today Tabs" subfolder if there are open tabs for this space
        if space_name in tabs_by_space and tabs_by_space[space_name]:
            today_tabs_folder = {
                "title": "Today Tabs",
                "type": "folder",
                "children": tabs_by_space[space_name],
            }
            # Insert "Today Tabs" at the beginning
            space_children.insert(0, today_tabs_folder)

        space_folder = {
            "title": space_name,
            "type": "folder",
            "children": space_children,
        }
        bookmarks["bookmarks"].append(space_folder)

    # No fallback - if filter produced nothing, return empty bookmarks
    # This ensures profile isolation and prevents combining bookmarks from all profiles
    return bookmarks

def _convert_bookmarks_to_html_legacy(bookmarks: dict) -> str:
    html_str = """<!DOCTYPE NETSCAPE-Bookmark-file-1>
<META HTTP-EQUIV="Content-Type" CONTENT="text/html; charset=UTF-8">
<TITLE>Bookmarks</TITLE>
<H1>Bookmarks</H1>
<DL><p>"""
    def traverse_dict(d: list, html_str: str, level: int) -> str:
        indent = "\t" * level
        for item in d:
            if item["type"] == "folder":
                html_str += f'\n{indent}<DT><H3>{item["title"]}</H3>'
                html_str += f"\n{indent}<DL><p>"
                html_str = traverse_dict(item["children"], html_str, level + 1)
                html_str += f"\n{indent}</DL><p>"
            elif item["type"] == "bookmark":
                html_str += f'\n{indent}<DT><A HREF="{item["url"]}">{item["title"]}</A>'
        return html_str
    html_str = traverse_dict(bookmarks["bookmarks"], html_str, 1)
    html_str += "\n</DL><p>"
    return html_str
