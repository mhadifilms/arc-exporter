"""Shared pytest fixtures.

Every fixture here builds *anonymous* data in a temp directory; no real Arc data is
ever read by the test suite.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from arc_exporter.crypto import derive_v10_key, encrypt_v10


@pytest.fixture(autouse=True)
def _reset_console_singleton():
    """``rich.Console`` is cached as a module-level singleton; reset between tests so
    width changes via COLUMNS env var are respected."""
    import arc_exporter.logging_setup as _ls

    _ls._console = None
    _ls._err_console = None
    yield
    _ls._console = None
    _ls._err_console = None


@pytest.fixture
def aes_key() -> bytes:
    """Deterministic v10 key derived from a fake Keychain secret."""
    return derive_v10_key("test-secret")


@pytest.fixture
def alt_key() -> bytes:
    """A second key, simulating Chrome's Safe Storage key being different from Arc's."""
    return derive_v10_key("other-secret")


@pytest.fixture
def fake_login_data(tmp_path: Path, aes_key: bytes) -> Path:
    db = tmp_path / "Login Data"
    conn = sqlite3.connect(str(db))
    try:
        conn.execute(
            "CREATE TABLE logins ("
            "origin_url TEXT NOT NULL, action_url TEXT, username_element TEXT, "
            "username_value TEXT, password_element TEXT, password_value BLOB, "
            "submit_element TEXT, signon_realm TEXT NOT NULL, date_created INTEGER NOT NULL, "
            "blacklisted_by_user INTEGER NOT NULL DEFAULT 0, scheme INTEGER NOT NULL DEFAULT 0)"
        )
        rows = [
            ("https://example.com/login", "alice@example.com", encrypt_v10("p@ss-1", aes_key)),
            ("https://github.com/", "bob", encrypt_v10("hunter2", aes_key)),
            ("https://broken.example.com/", "carol", b"not-v10"),
        ]
        for url, user, blob in rows:
            conn.execute(
                "INSERT INTO logins (origin_url, username_value, password_value, signon_realm, "
                "date_created) VALUES (?, ?, ?, ?, ?)",
                (url, user, blob, url, 13300000000000000),
            )
        conn.commit()
    finally:
        conn.close()
    return db


@pytest.fixture
def fake_web_data(tmp_path: Path, aes_key: bytes) -> Path:
    db = tmp_path / "Web Data"
    conn = sqlite3.connect(str(db))
    try:
        conn.execute(
            "CREATE TABLE credit_cards (name_on_card TEXT, expiration_month INTEGER, "
            "expiration_year INTEGER, card_number_encrypted BLOB)"
        )
        conn.execute(
            "INSERT INTO credit_cards VALUES (?, ?, ?, ?)",
            ("Alice Example", 12, 2030, encrypt_v10("4111111111111111", aes_key)),
        )
        conn.execute(
            "INSERT INTO credit_cards VALUES (?, ?, ?, ?)",
            ("Bob Example", 6, 2028, encrypt_v10("5500000000000004", aes_key)),
        )
        conn.commit()
    finally:
        conn.close()
    return db


@pytest.fixture
def fake_cookies(tmp_path: Path) -> Path:
    db = tmp_path / "Cookies"
    conn = sqlite3.connect(str(db))
    try:
        conn.execute(
            "CREATE TABLE cookies ("
            "host_key TEXT, name TEXT, value TEXT, encrypted_value BLOB, path TEXT, "
            "expires_utc INTEGER, is_secure INTEGER, is_httponly INTEGER, samesite INTEGER, "
            "creation_utc INTEGER, last_access_utc INTEGER)"
        )
        conn.execute(
            "INSERT INTO cookies VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "example.com",
                "session",
                "abc123",
                b"",
                "/",
                13400000000000000,
                1,
                1,
                1,
                13300000000000000,
                13350000000000000,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return db


@pytest.fixture
def fake_history(tmp_path: Path) -> Path:
    db = tmp_path / "History"
    conn = sqlite3.connect(str(db))
    try:
        conn.execute(
            "CREATE TABLE urls (url TEXT, title TEXT, visit_count INTEGER, typed_count INTEGER, last_visit_time INTEGER)"
        )
        conn.executemany(
            "INSERT INTO urls VALUES (?, ?, ?, ?, ?)",
            [
                ("https://news.example.com/", "Example News", 10, 1, 13400000000000000),
                ("https://docs.python.org/", "Python Docs", 99, 5, 13399000000000000),
            ],
        )
        conn.commit()
    finally:
        conn.close()
    return db


@pytest.fixture
def fake_sidebar() -> dict:
    """A minimal but realistic StorableSidebar.json shape covering pinned, today tabs, splits, and groups."""
    space_id = "S1"
    pinned_container = "PIN1"
    unpinned_container = "UNP1"
    folder_id = "F1"
    tab_a, tab_b, tab_c, tab_d = "TAB-A", "TAB-B", "TAB-C", "TAB-D"
    split_id, split_left, split_right = "SPLIT-1", "TAB-SL", "TAB-SR"
    return {
        "sidebar": {
            "containers": [
                {"global": {}},
                {
                    "spaces": [
                        space_id,
                        {
                            "title": "Personal",
                            "profile": {"default": {}},
                            "newContainerIDs": [
                                {"pinned": {}},
                                pinned_container,
                                {"unpinned": {}},
                                unpinned_container,
                            ],
                        },
                    ],
                    "items": [
                        pinned_container,
                        {"childrenIds": [tab_a, folder_id]},
                        tab_a,
                        {
                            "title": "Tab A",
                            "data": {"tab": {"savedTitle": "Tab A", "savedURL": "https://a.example.com/"}},
                        },
                        folder_id,
                        {"title": "Work", "childrenIds": [tab_b]},
                        tab_b,
                        {
                            "data": {
                                "tab": {
                                    "savedTitle": "Tab B & <Friends>",
                                    "savedURL": "https://b.example.com/?x=1&y=2",
                                }
                            }
                        },
                        unpinned_container,
                        {"childrenIds": [tab_c, split_id]},
                        tab_c,
                        {
                            "title": "Tab C",
                            "data": {"tab": {"savedTitle": "Tab C", "savedURL": "https://c.example.com/"}},
                        },
                        split_id,
                        {"childrenIds": [split_left, split_right], "data": {"splitView": {}}},
                        split_left,
                        {
                            "title": "Left",
                            "data": {"tab": {"savedTitle": "Left", "savedURL": "https://left.example.com/"}},
                        },
                        split_right,
                        {
                            "title": "Right",
                            "data": {
                                "tab": {"savedTitle": "Right", "savedURL": "https://right.example.com/"}
                            },
                        },
                        tab_d,
                        {"title": "Dangling", "data": {"tab": {"savedTitle": "", "savedURL": ""}}},
                    ],
                },
            ]
        }
    }


@pytest.fixture
def fake_arc_root(tmp_path: Path, fake_sidebar: dict) -> Path:
    """A directory that looks enough like ``~/Library/Application Support/Arc`` for tests."""
    root = tmp_path / "Arc"
    user_data = root / "User Data"
    user_data.mkdir(parents=True)
    profile = user_data / "Default"
    profile.mkdir()
    (profile / "Preferences").write_text(
        json.dumps({"extensions": {"settings": {}}}),
        encoding="utf-8",
    )
    (user_data / "Local State").write_text(
        json.dumps(
            {
                "profile": {
                    "info_cache": {
                        "Default": {"name": "Personal"},
                        "__ARC_SYSTEM_PROFILE": {"name": "__ARC_SYSTEM_PROFILE"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    (root / "StorableSidebar.json").write_text(json.dumps(fake_sidebar), encoding="utf-8")
    return root
