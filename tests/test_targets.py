from __future__ import annotations

from pathlib import Path

import pytest

from arc_exporter.errors import TargetUnavailableError
from arc_exporter.targets.chromium import ChromiumTarget


def test_chromium_create_profile_picks_first_free(tmp_path: Path):
    target = ChromiumTarget(
        name="chrome", root_dir=tmp_path, services=("Chrome Safe Storage",), process="Google Chrome"
    )
    (tmp_path / "Profile 1").mkdir()
    (tmp_path / "Profile 3").mkdir()
    p = target.create_profile("Alice")
    assert p.directory_name == "Profile 2"


def test_chromium_register_uses_final_directory(tmp_path: Path):
    """Regression: legacy code registered the original dst.name even after collision-rename."""
    target = ChromiumTarget(
        name="chrome", root_dir=tmp_path, services=("Chrome Safe Storage",), process="Google Chrome"
    )
    # Simulate a pre-existing Profile 1 (so create_profile picks Profile 2),
    # then call copy_arc_profile which itself may pick a collision suffix.
    arc_profile = tmp_path / "arc_source"
    arc_profile.mkdir()
    (arc_profile / "Preferences").write_text("{}", encoding="utf-8")
    (tmp_path / "Profile 1").mkdir()  # so create_profile() picks "Profile 2"
    # Pre-create the would-be destination so safe_copy_tree must allocate a new name.
    (tmp_path / "Profile 2").mkdir()

    result = target.copy_arc_profile(arc_profile, "Alice")
    # Registered name must match the actual destination directory on disk
    local_state = tmp_path / "Local State"
    assert local_state.exists()
    import json

    state = json.loads(local_state.read_text(encoding="utf-8"))
    info_cache = state["profile"]["info_cache"]
    assert result.directory_name in info_cache
    assert info_cache[result.directory_name]["name"] == "Alice"


def test_chromium_not_installed_raises(tmp_path: Path):
    target = ChromiumTarget(name="chrome", root_dir=tmp_path / "missing", services=(), process="x")
    with pytest.raises(TargetUnavailableError):
        target.create_profile("Alice")


def test_reencrypt_cookies_rewrites_v10_blobs(tmp_path: Path):
    """Cookies copied from Arc must be re-encrypted under the target's Safe Storage key.

    Without this pass every session cookie reads as garbage in the target browser and
    the user is signed out of every site.
    """
    import sqlite3

    from arc_exporter.crypto import decrypt_v10, encrypt_v10, looks_like_v10
    from arc_exporter.targets.base import TargetProfile

    arc_key = b"\x01" * 16
    target_key = b"\x02" * 16
    profile_path = tmp_path / "Profile 1"
    profile_path.mkdir()
    db_path = profile_path / "Cookies"
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute(
            "CREATE TABLE cookies (host_key TEXT, name TEXT, encrypted_value BLOB, samesite INTEGER)"
        )
        conn.executemany(
            "INSERT INTO cookies (host_key, name, encrypted_value, samesite) VALUES (?, ?, ?, ?)",
            [
                ("example.com", "sid", encrypt_v10("abc-123", arc_key), 0),
                ("example.com", "auth", encrypt_v10("xyzpdq", arc_key), 0),
                ("malformed.com", "stale", b"v10notreallyencrypted", 0),
                ("plaintext.com", "raw", b"", 0),
            ],
        )

    target = ChromiumTarget(
        name="chrome", root_dir=tmp_path, services=("Chrome Safe Storage",), process="Google Chrome"
    )
    tp = TargetProfile(directory_name="Profile 1", display_name="Profile 1", path=profile_path)

    n = target._reencrypt_cookies(tp, arc_aes_key=arc_key, target_aes_key=target_key)
    assert n == 2  # only the two well-formed v10 rows; the rest are skipped

    with sqlite3.connect(str(db_path)) as conn:
        conn.text_factory = bytes
        rows = conn.execute("SELECT host_key, name, encrypted_value FROM cookies ORDER BY name").fetchall()
    by_name = {name.decode(): (host.decode(), ev) for host, name, ev in rows}
    assert decrypt_v10(by_name["auth"][1], target_key) == "xyzpdq"
    assert decrypt_v10(by_name["sid"][1], target_key) == "abc-123"
    # Bad v10 row still has v10 prefix but un-decryptable
    assert looks_like_v10(by_name["stale"][1])
    assert by_name["raw"][1] == b""


def test_reencrypt_cookies_noop_when_keys_missing(tmp_path: Path):
    import sqlite3

    from arc_exporter.targets.base import TargetProfile

    profile_path = tmp_path / "Profile 1"
    profile_path.mkdir()
    db_path = profile_path / "Cookies"
    with sqlite3.connect(str(db_path)) as conn:
        conn.execute("CREATE TABLE cookies (encrypted_value BLOB)")
        conn.execute("INSERT INTO cookies (encrypted_value) VALUES (?)", (b"v10anything",))

    target = ChromiumTarget(
        name="chrome", root_dir=tmp_path, services=("Chrome Safe Storage",), process="Google Chrome"
    )
    tp = TargetProfile(directory_name="Profile 1", display_name="Profile 1", path=profile_path)

    assert target._reencrypt_cookies(tp, arc_aes_key=None, target_aes_key=b"\x02" * 16) == 0
    assert target._reencrypt_cookies(tp, arc_aes_key=b"\x01" * 16, target_aes_key=None) == 0


def test_arc_webstore_extension_ids_filters_correctly(tmp_path: Path):
    """Only true Web-Store extensions should be picked up for the External
    Extensions install pass. Chrome built-ins (Web Store launcher, PDF
    viewer, Hangouts) are stored at ``location=5`` in Arc's prefs but with
    ``from_webstore=false`` and no ``update_url``; they must be skipped or
    they'll show up as "did not auto-install" warnings every run.
    """
    import json

    from arc_exporter.targets.chromium import _arc_webstore_extension_ids

    profile = tmp_path / "Default"
    profile.mkdir()
    sp = profile / "Secure Preferences"
    real_id_a = "a" * 32  # INTERNAL + from_webstore + Web Store update_url -> kept
    real_id_b = "b" * 32  # EXTERNAL_PREF_DOWNLOAD + from_webstore + WS update_url -> kept
    chrome_builtin = "f" * 32  # location=5 BUT from_webstore=false (Chrome PDF viewer etc.) -> dropped
    component = "c" * 32  # COMPONENT -> dropped
    policy = "d" * 32  # EXTERNAL_POLICY_DOWNLOAD -> dropped
    private_update = "e" * 32  # INTERNAL but private (non-Web-Store) update_url -> dropped
    junk_id = "not-a-real-id"
    sp.write_text(
        json.dumps(
            {
                "extensions": {
                    "settings": {
                        real_id_a: {
                            "location": 1,
                            "from_webstore": True,
                            "manifest": {"update_url": "https://clients2.google.com/service/update2/crx"},
                        },
                        real_id_b: {
                            "location": 5,
                            "from_webstore": True,
                            "manifest": {"update_url": "https://clients2.google.com/service/update2/crx"},
                        },
                        chrome_builtin: {
                            "location": 5,
                            "from_webstore": False,  # the magic discriminator
                            "manifest": {"name": "Chromium PDF Viewer"},
                        },
                        component: {"location": 4, "from_webstore": False, "manifest": {}},
                        policy: {"location": 6, "from_webstore": True, "manifest": {}},
                        private_update: {
                            "location": 1,
                            "from_webstore": True,
                            "manifest": {"update_url": "https://example.com/updates.xml"},
                        },
                        junk_id: {"location": 1, "from_webstore": True},
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    ids = _arc_webstore_extension_ids(profile)
    assert ids == sorted([real_id_a, real_id_b])


def test_strip_extension_state_clears_settings_and_macs(tmp_path: Path):
    """Stripping must remove ``extensions.settings`` AND their MAC leaves so the
    resigner doesn't sign signatures for non-existent entries."""
    from arc_exporter.targets.chromium import _strip_extension_state

    prefs = {
        "extensions": {
            "settings": {"a" * 32: {"location": 1}},
            "install_signature": {"ids": ["a" * 32]},
            "pending_updates": {"foo": "bar"},
            "pinned_extensions": ["a" * 32],  # purely cosmetic, must survive
        },
        "protection": {
            "macs": {
                "extensions": {
                    "settings": {"a" * 32: "deadbeef"},
                    "install_signature": "feed",
                },
                "profile": {"name": "abc123"},  # must survive
            }
        },
        "profile": {"name": "Alice"},
    }
    _strip_extension_state(prefs)
    assert "settings" not in prefs["extensions"]
    assert "install_signature" not in prefs["extensions"]
    assert "pending_updates" not in prefs["extensions"]
    assert prefs["extensions"]["pinned_extensions"] == ["a" * 32]
    assert "settings" not in prefs["protection"]["macs"]["extensions"]
    assert "install_signature" not in prefs["protection"]["macs"]["extensions"]
    assert prefs["protection"]["macs"]["profile"] == {"name": "abc123"}
    assert prefs["profile"]["name"] == "Alice"


def test_external_extensions_install_skips_when_binary_missing(tmp_path: Path):
    from arc_exporter.targets.external_extensions import install_extensions_for_profile

    profile_path = tmp_path / "Profile 1"
    profile_path.mkdir()
    ext_dir = tmp_path / "External Extensions"

    installed, missed = install_extensions_for_profile(
        extension_ids=["a" * 32, "b" * 32],
        target_profile_path=profile_path,
        browser_binary=None,
        external_extensions_dir=ext_dir,
        timeout_s=1.0,
    )
    assert installed == []
    assert sorted(missed) == ["a" * 32, "b" * 32]


def test_external_extensions_install_empty_input(tmp_path: Path):
    from arc_exporter.targets.external_extensions import install_extensions_for_profile

    profile_path = tmp_path / "Profile 1"
    profile_path.mkdir()
    installed, missed = install_extensions_for_profile(
        extension_ids=[],
        target_profile_path=profile_path,
        browser_binary=None,
        external_extensions_dir=tmp_path / "ext",
        timeout_s=1.0,
    )
    assert installed == []
    assert missed == []


def test_auto_enable_extensions_flips_state_and_resigns(tmp_path: Path):
    """After Chrome installs External Extensions it leaves them disabled +
    flagged ``location=6`` (EXTERNAL_PREF_DOWNLOAD). The helper must:

    - flip ``state`` to 1 and clear ``disable_reasons`` so the extension
      is actually usable on next launch,
    - promote ``location`` 6 -> 1 (INTERNAL) so Chrome's auto-cleanup of
      descriptor-managed extensions doesn't wipe everything we just
      installed when phase 2 relaunches Chrome with the descriptor files
      already gone (this was the "0 extensions installed" regression
      seen on Profile 2),
    - resign the resulting tree so Chromium accepts the edits past the
      next launch.

    Extensions outside the installed-list must be left strictly alone.
    """
    import json

    from arc_exporter.targets.chromium import _auto_enable_extensions
    from arc_exporter.targets.secure_prefs import calculate, machine_id, seed_for

    profile = tmp_path / "Profile 1"
    profile.mkdir()
    sp_path = profile / "Secure Preferences"
    ext_a = "a" * 32
    ext_b = "b" * 32
    ext_c = "c" * 32  # not in our installed list -> must NOT be touched
    sp_path.write_text(
        json.dumps(
            {
                "extensions": {
                    "settings": {
                        ext_a: {
                            "state": 0,
                            "disable_reasons": [2048],
                            "location": 6,
                            "was_installed_by_default": True,
                        },
                        ext_b: {
                            "state": 0,
                            "disable_reasons": [2048],
                            "location": 6,
                            "was_installed_by_default": True,
                        },
                        ext_c: {
                            "state": 0,
                            "disable_reasons": [2048],
                            "location": 6,
                            "was_installed_by_default": True,
                        },
                    }
                },
                # Mirror the real shape Chrome 137+ writes: each entry under
                # ``settings`` has a sibling encrypted hash under
                # ``settings_encrypted_hash``. The resigner must rewrite BOTH
                # for any entry whose underlying value changed.
                "protection": {
                    "macs": {
                        "extensions": {
                            "settings": {
                                ext_a: "placeholder",
                                ext_b: "placeholder",
                                ext_c: "placeholder",
                            },
                            "settings_encrypted_hash": {
                                ext_a: "placeholder",
                                ext_b: "placeholder",
                                ext_c: "placeholder",
                            },
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    fake_aes_key = b"0123456789abcdef"  # any 16-byte key works for the test

    n = _auto_enable_extensions(
        "chrome", profile, [ext_a, ext_b], target_aes_key=fake_aes_key
    )
    assert n == 2

    out = json.loads(sp_path.read_text(encoding="utf-8"))
    settings = out["extensions"]["settings"]
    # Touched entries: enabled, no disable reasons, promoted to INTERNAL.
    for ext_id in (ext_a, ext_b):
        meta = settings[ext_id]
        assert meta["state"] == 1
        assert meta["disable_reasons"] == []
        assert meta["location"] == 1, (
            "must promote 6 (EXTERNAL_PREF_DOWNLOAD) to 1 (INTERNAL) so "
            "Chrome doesn't auto-uninstall when the descriptor file is gone"
        )
        assert meta["was_installed_by_default"] is False
        assert meta["was_installed_by_oem"] is False
    # Untouched entry must keep its original sideload-flavored state intact.
    assert settings[ext_c]["state"] == 0
    assert settings[ext_c]["location"] == 6
    assert settings[ext_c]["disable_reasons"] == [2048]

    # MACs must be regenerated for the entries we touched, matching what
    # Chromium itself would compute for the new values (location=1 now).
    from arc_exporter.targets.secure_prefs import calculate_encrypted

    seed = seed_for("chrome")
    device = machine_id()
    expected_a = calculate(seed, device, f"extensions.settings.{ext_a}", settings[ext_a])
    actual_a = out["protection"]["macs"]["extensions"]["settings"][ext_a]
    assert actual_a == expected_a

    # Encrypted hashes must be present too — without them, Chrome 137+
    # silently wipes every entry whose underlying value changed (this
    # was the literal "0 extensions installed" bug). Chrome stores both
    # the legacy hex HMAC and the OSCrypt-encrypted SHA256 side-by-side
    # under ``protection.macs.extensions.settings_encrypted_hash``.
    enc_settings = out["protection"]["macs"]["extensions"].get("settings_encrypted_hash") or {}
    assert ext_a in enc_settings, "encrypted hash must be written for promoted extensions"
    expected_enc_a = calculate_encrypted(
        seed, fake_aes_key, f"extensions.settings.{ext_a}", settings[ext_a]
    )
    assert enc_settings[ext_a] == expected_enc_a


def test_auto_enable_extensions_noop_when_empty(tmp_path: Path):
    """Helper must be a clean no-op when no extensions were installed."""
    from arc_exporter.targets.chromium import _auto_enable_extensions

    profile = tmp_path / "Profile 1"
    profile.mkdir()
    # No Secure Preferences file even — must still be safe.
    assert _auto_enable_extensions("chrome", profile, []) == 0


def test_external_extensions_install_filters_bad_ids(tmp_path: Path):
    """Only well-formed 32-char lowercase alpha IDs should produce descriptors."""
    from arc_exporter.targets.external_extensions import install_extensions_for_profile

    profile_path = tmp_path / "Profile 1"
    profile_path.mkdir()
    ext_dir = tmp_path / "External Extensions"
    installed, missed = install_extensions_for_profile(
        extension_ids=["short", "A" * 32, "x" * 32, "1" * 32],  # only "xxx..." is valid
        target_profile_path=profile_path,
        browser_binary=None,
        external_extensions_dir=ext_dir,
        timeout_s=1.0,
    )
    assert installed == []
    assert missed == ["x" * 32]


def test_external_extensions_descriptors_persist_after_install(tmp_path: Path, monkeypatch):
    """Critical regression check: descriptor JSON files MUST stay on disk
    after ``install_extensions_for_profile`` returns.

    Chrome 142+ deletes any ``location=6`` extension whose backing
    descriptor file is missing on a subsequent launch — that was the
    root cause of every previous "0 extensions installed" report. The
    fix is to leave the per-extension ``<id>.json`` pointers in
    ``External Extensions/`` permanently as Chrome's source-of-truth.

    We mock out the actual Chrome subprocess + polling so this test
    runs in milliseconds.
    """
    import subprocess

    from arc_exporter.targets import external_extensions as ee

    profile = tmp_path / "Profile 1"
    profile.mkdir()
    ext_dir = tmp_path / "External Extensions"
    binary = tmp_path / "fake-chrome"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(0o755)

    # Pretend Chrome ran instantly and "installed" the two extensions.
    class _DummyProc:
        def poll(self):
            return 0

        def wait(self, timeout=None):
            return 0

        def terminate(self):
            pass

        def kill(self):
            pass

    monkeypatch.setattr(subprocess, "Popen", lambda *a, **kw: _DummyProc())
    monkeypatch.setattr(
        ee,
        "_poll_extensions_done",
        lambda **kwargs: set(kwargs["wanted"]),
    )

    ids = ["a" * 32, "b" * 32]
    installed, missed = ee.install_extensions_for_profile(
        extension_ids=ids,
        target_profile_path=profile,
        browser_binary=binary,
        external_extensions_dir=ext_dir,
        timeout_s=1.0,
    )
    assert sorted(installed) == sorted(ids)
    assert missed == []
    # The whole point of this test: descriptors are STILL there after
    # install. If a future refactor reintroduces the cleanup-after-phase-1
    # loop, this assertion catches it before users see "0 extensions".
    for ext_id in ids:
        assert (ext_dir / f"{ext_id}.json").exists()


def test_set_session_restore_continue_writes_pref():
    """The migration must flip ``session.restore_on_startup`` to 1 so that
    tabs opened by the bootstrap extension survive the next Chrome launch.

    A fresh Chrome profile defaults to ``5`` (Open NTP), which would silently
    discard the tabs we just opened.
    """
    from arc_exporter.targets.chromium import _set_session_restore_continue

    prefs: dict = {"session": {"restore_on_startup": 5, "startup_urls": ["https://leftover/"]}}
    _set_session_restore_continue(prefs)
    assert prefs["session"]["restore_on_startup"] == 1
    assert "startup_urls" not in prefs["session"]


def test_set_session_restore_continue_creates_missing_section():
    """If the profile's ``Preferences`` had no ``session`` block at all we
    still need to leave one in place — Chrome reads the file at startup and
    falls back to per-build defaults otherwise."""
    from arc_exporter.targets.chromium import _set_session_restore_continue

    prefs: dict = {"profile": {"name": "Main"}}
    _set_session_restore_continue(prefs)
    assert prefs["session"]["restore_on_startup"] == 1


def test_launch_chrome_with_tabs_no_urls(tmp_path: Path):
    """With no URLs to open, phase 2 must be a no-op (no Chrome launch attempted)."""
    from arc_exporter.targets.external_extensions import launch_chrome_with_tabs

    profile = tmp_path / "Profile 1"
    profile.mkdir()
    n = launch_chrome_with_tabs(
        target_profile_path=profile,
        browser_binary=tmp_path / "nope",  # would EFAULT if we actually exec'd
        urls=[],
    )
    assert n == 0


def test_walk_bookmark_urls_flattens_folders():
    """Folders, no matter how deeply nested, contribute their leaf URLs only.

    The fact that Arc nests pinned folders 2+ levels deep is important for
    the URL list we hand Chrome — we need every leaf in left-to-right
    visual order, with intermediate folder names discarded.
    """
    from arc_exporter.parsers.sidebar import BookmarkNode
    from arc_exporter.targets.chromium import _walk_bookmark_urls

    nested = BookmarkNode(
        title="education",
        kind="folder",
        children=[
            BookmarkNode(title="khan", kind="bookmark", url="https://khanacademy.org/"),
            BookmarkNode(
                title="math",
                kind="folder",
                children=[
                    BookmarkNode(title="3b1b", kind="bookmark", url="https://3blue1brown.com/"),
                ],
            ),
        ],
    )
    urls = _walk_bookmark_urls(nested)
    assert urls == ["https://khanacademy.org/", "https://3blue1brown.com/"]


def test_walk_bookmark_urls_handles_bookmark_with_no_url():
    """A bookmark node with ``url=None`` (rare but seen in malformed sidebars)
    must just be skipped rather than crash the URL build."""
    from arc_exporter.parsers.sidebar import BookmarkNode
    from arc_exporter.targets.chromium import _walk_bookmark_urls

    n = BookmarkNode(title="orphan", kind="bookmark", url=None)
    assert _walk_bookmark_urls(n) == []


def test_build_tab_urls_pinned_first_then_today_dedupe(tmp_path: Path, fake_sidebar: dict):
    """Pinned URLs must come first (so Chrome puts them leftmost), today-tabs
    after, and we should NOT drop today-tab URLs even if a pinned folder
    contained the same URL.

    The fake_sidebar fixture is exercised by tests/test_sidebar.py so its
    contents are well-understood: pinned has tab-a + folder(Work → tab-b),
    today has tab-c + split(left, right). We reuse it here so a future
    schema change on either side surfaces failures in both suites.
    """
    import json

    from arc_exporter.targets.base import MigrationRequest
    from arc_exporter.targets.chromium import _build_tab_urls

    sidebar_path = tmp_path / "StorableSidebar.json"
    sidebar_path.write_text(json.dumps(fake_sidebar), encoding="utf-8")

    class _FakeSource:
        directory_name = "Default"  # fake_sidebar uses {"profile": {"default": {}}}
        path = tmp_path

    req = MigrationRequest(artefact_paths={}, arc_sidebar_path=sidebar_path)
    urls = _build_tab_urls(_FakeSource(), req)

    # Pinned URLs must appear before today-tab URLs.
    assert urls.index("https://a.example.com/") < urls.index("https://c.example.com/")
    assert urls.index("https://b.example.com/?x=1&y=2") < urls.index("https://c.example.com/")
    # Today's split-view children come through as ordinary tabs too.
    assert "https://left.example.com/" in urls
    assert "https://right.example.com/" in urls
    # Dangling (empty URL) entries don't make it into the list.
    assert "" not in urls


def test_build_tab_urls_returns_empty_when_no_sidebar(tmp_path: Path):
    """Partial migrations (e.g. ``--only=extensions``) don't carry a
    sidebar path; phase 2 just becomes a no-op rather than blowing up."""
    from arc_exporter.targets.base import MigrationRequest
    from arc_exporter.targets.chromium import _build_tab_urls

    class _FakeSource:
        directory_name = "P-1"
        path = tmp_path

    req = MigrationRequest(artefact_paths={}, arc_sidebar_path=None)
    assert _build_tab_urls(_FakeSource(), req) == []
