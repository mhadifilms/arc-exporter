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
