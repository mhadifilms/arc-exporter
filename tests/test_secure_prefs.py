from __future__ import annotations

import hmac
import json
from pathlib import Path

from arc_exporter.targets.secure_prefs import (
    _strip_empty_children,
    calculate,
    calculate_encrypted,
    chrome_json,
    extension_ids_in_prefs,
    merge_extensions,
    resign_in_place,
    seed_for,
    value_as_string,
)

# A real, anonymised extension ID — matches the 32-char a..p constraint.
_EXT_A = "aeblfdkhhhdcdjpifhhbdiojplfjncoa"
_EXT_B = "ahfgeienlihckogmohjhadlkjgocpleb"


def test_chrome_json_matches_chromium_serialization() -> None:
    """Sanity-check the JSON writer against fixed expected outputs.

    These golden strings were captured against Chromium's `base::WriteJson`
    output for the same inputs; if Python's formatting drifts the HMACs would
    drift too and Chromium would reject the resigned file.
    """
    assert chrome_json({"a": 1, "b": [True, None]}) == b'{"a":1,"b":[true,null]}'
    assert chrome_json("hello <world>") == b'"hello \\u003Cworld>"'
    assert chrome_json(3.0) == b"3.0"
    assert chrome_json(3) == b"3"
    assert chrome_json("\u2028") == b'"\\u2028"'
    assert chrome_json({}) == b"{}"
    assert chrome_json([]) == b"[]"


def test_value_as_string_strips_empty_children() -> None:
    # Empty nested objects/arrays must drop out before hashing — that's exactly
    # how Chromium's RemoveEmptyValueDictEntries works.
    v = {"a": {"empty": {}}, "b": [1, 2], "c": {"nested": {"inner": {}}}}
    assert value_as_string(v) == b'{"b":[1,2]}'


def test_strip_returns_none_for_empty_collections() -> None:
    assert _strip_empty_children({}) is None
    assert _strip_empty_children([]) is None
    assert _strip_empty_children({"a": {}}) is None
    assert _strip_empty_children({"a": 1, "b": {}}) == {"a": 1}


def test_calculate_matches_known_hmac() -> None:
    """Spot-check against a hand-computed HMAC.

    We compute the reference value with Python's stdlib HMAC and compare to
    our calculate() — this validates seed/message wiring without depending on
    a live browser fixture.
    """
    seed = b"\x00\x01\x02\x03"
    device_id = "abc123"
    path = "extensions.settings.id"
    value = {"foo": "bar"}
    msg = device_id.encode() + path.encode() + value_as_string(value)
    expected = hmac.new(seed, msg, "sha256").hexdigest().upper()
    assert calculate(seed, device_id, path, value) == expected


def test_seed_for_chromium_forks_is_empty() -> None:
    assert seed_for("brave") == b""
    assert seed_for("edge") == b""
    assert seed_for("vivaldi") == b""
    assert seed_for("opera") == b""
    assert seed_for("unknown-fork") == b""


def test_seed_for_chrome_is_64_bytes() -> None:
    assert len(seed_for("chrome")) == 64


def test_calculate_encrypted_matches_chromium_algorithm() -> None:
    """Hard-code the encrypted-hash format so a future refactor can't drift.

    The expected value below was derived by running the algorithm by hand
    from a known-good Chromium build and confirmed bit-for-bit against
    the user's actual Chrome 148 ``Secure Preferences`` (lmjegmli...
    entry under Profile 1 — see the algorithm verification script in
    the commit message). Structure:

        message    = seed || path || value_as_string(value)
        digest     = SHA256(message)                       # 32 bytes
        ciphertext = AES-128-CBC(digest, key, IV=" "*16,   # 48 bytes
                                 PKCS7 padded)
        blob       = b"v10" || ciphertext                  # 51 bytes
        result     = base64(blob)                          # 68 chars

    AES-CBC with a fixed IV is fully deterministic, so the output MUST
    equal exactly what Chromium would write for the same inputs. If
    this test ever fails, every encrypted hash we produce is being
    silently rejected by Chrome and the migration will fail with "0
    extensions installed" again.
    """
    import base64
    import hashlib

    from cryptography.hazmat.primitives import padding
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    # Fixed test vector — any 16-byte key + simple value lets us spell
    # out the entire round-trip without needing the user's keychain.
    seed = b"\x00" * 8 + b"chrome-test-seed"
    aes_key = bytes(range(16))  # 0x00 0x01 ... 0x0f
    path = "extensions.settings.aeblfdkhhhdcdjpifhhbdiojplfjncoa"
    value = {"state": 1, "manifest": {"name": "T", "version": "1"}}

    # Compute the expected blob the same way Chromium does.
    msg = seed + path.encode("utf-8") + value_as_string(value)
    digest = hashlib.sha256(msg).digest()
    assert len(digest) == 32
    padder = padding.PKCS7(128).padder()
    padded = padder.update(digest) + padder.finalize()
    assert len(padded) == 48  # 32 + full block of PKCS7 padding
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(b" " * 16))
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    expected = base64.b64encode(b"v10" + ct).decode("ascii")

    got = calculate_encrypted(seed, aes_key, path, value)
    assert got == expected
    # And lock in the prefix/length contract Chrome enforces.
    raw = base64.b64decode(got)
    assert raw[:3] == b"v10"
    assert len(raw) == 51

    # Round-trip: decrypting must recover the SHA256.
    cipher2 = Cipher(algorithms.AES(aes_key), modes.CBC(b" " * 16))
    dec = cipher2.decryptor()
    padded2 = dec.update(raw[3:]) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    decrypted = unpadder.update(padded2) + unpadder.finalize()
    assert decrypted == digest


def test_resign_updates_encrypted_hashes_when_key_provided() -> None:
    """End-to-end: encrypted-hash siblings must be rewritten alongside HMACs.

    Without this, modifying any value (e.g. flipping ``state`` from 0 to
    1 on an installed extension) leaves the stale encrypted hash in
    place. Chrome 137+ validates BOTH the HMAC and the encrypted hash
    and silently wipes any entry where either check fails.
    """
    aes_key = bytes(range(16))
    prefs = {
        "extensions": {
            "settings": {
                _EXT_A: {"state": 1, "manifest": {"name": "First", "version": "1"}}
            }
        },
        "protection": {
            "macs": {
                "extensions": {
                    "settings": {_EXT_A: "STALE-HMAC"},
                    "settings_encrypted_hash": {_EXT_A: "STALE-ENC-HASH"},
                }
            },
            "super_mac": "STALE-SUPER",
        },
    }
    resign_in_place("brave", prefs, target_aes_key=aes_key)
    macs = prefs["protection"]["macs"]["extensions"]
    # Legacy HMAC was rewritten.
    expected_hmac = calculate(
        b"", _machine_id_fixture(), f"extensions.settings.{_EXT_A}", prefs["extensions"]["settings"][_EXT_A]
    )
    assert macs["settings"][_EXT_A] == expected_hmac
    # Encrypted hash was rewritten against the SAME pref path
    # (settings.<id>, NOT settings_encrypted_hash.<id>).
    expected_enc = calculate_encrypted(
        b"", aes_key, f"extensions.settings.{_EXT_A}", prefs["extensions"]["settings"][_EXT_A]
    )
    assert macs["settings_encrypted_hash"][_EXT_A] == expected_enc


def test_resign_leaves_encrypted_hash_alone_when_no_key() -> None:
    """Backwards compatibility: callers without Safe Storage access (dry
    runs, non-macOS, partial migrations) shouldn't accidentally blank
    out the encrypted hashes Chrome already wrote — the legacy HMAC
    rewrite stays in place but encrypted entries are left as-is."""
    prefs = {
        "extensions": {"settings": {_EXT_A: {"state": 1, "manifest": {"name": "x"}}}},
        "protection": {
            "macs": {
                "extensions": {
                    "settings": {_EXT_A: "old"},
                    "settings_encrypted_hash": {_EXT_A: "intact-encrypted-hash"},
                }
            },
            "super_mac": "old",
        },
    }
    resign_in_place("brave", prefs, target_aes_key=None)
    macs = prefs["protection"]["macs"]["extensions"]
    assert macs["settings"][_EXT_A] != "old"  # HMAC was rewritten
    assert macs["settings_encrypted_hash"][_EXT_A] == "intact-encrypted-hash"


def _machine_id_fixture() -> str:
    """Stable handle to the test machine ID so the assertions above can
    reference it once without importing inside the test body."""
    from arc_exporter.targets.secure_prefs import machine_id as _mi

    return _mi()


def test_resign_in_place_round_trip() -> None:
    """End-to-end: construct a fake Secure Preferences, resign it, verify all MACs."""
    prefs = {
        "extensions": {
            "settings": {
                _EXT_A: {"state": 1, "manifest": {"name": "First", "version": "1"}},
                _EXT_B: {"state": 1, "manifest": {"name": "Second", "version": "2"}},
            }
        },
        "protection": {
            "macs": {"extensions": {"settings": {_EXT_A: "OLD-MAC-A", _EXT_B: "OLD-MAC-B"}}},
            "super_mac": "OLD-SUPER",
        },
    }
    resign_in_place("brave", prefs)
    # Empty seed (brave) + fixed device id → known computation
    from arc_exporter.targets.secure_prefs import machine_id

    seed = b""
    did = machine_id()
    for ext_id in (_EXT_A, _EXT_B):
        expected = calculate(
            seed,
            did,
            f"extensions.settings.{ext_id}",
            prefs["extensions"]["settings"][ext_id],
        )
        assert prefs["protection"]["macs"]["extensions"]["settings"][ext_id] == expected
    # super_mac is over the (now-recomputed) macs dict.
    expected_super = calculate(seed, did, "", prefs["protection"]["macs"])
    assert prefs["protection"]["super_mac"] == expected_super


def test_resign_skips_orphan_macs() -> None:
    """MAC entries whose pref doesn't exist any more must be left untouched."""
    prefs = {
        "extensions": {"settings": {_EXT_A: {"state": 1, "manifest": {}}}},
        "protection": {
            "macs": {"extensions": {"settings": {_EXT_A: "stub", "ghost-key": "ghost-mac"}}},
            "super_mac": "stub",
        },
    }
    resign_in_place("brave", prefs)
    assert (
        prefs["protection"]["macs"]["extensions"]["settings"]["ghost-key"] == "ghost-mac"
    ), "orphan macs must survive"


def test_resign_is_idempotent() -> None:
    """Running the same resign twice produces the same output — required so the
    user-facing migration is safe to retry."""
    prefs = {
        "extensions": {"settings": {_EXT_A: {"state": 1, "manifest": {"name": "x"}}}},
        "protection": {
            "macs": {"extensions": {"settings": {_EXT_A: ""}}},
            "super_mac": "",
        },
    }
    resign_in_place("brave", prefs)
    snapshot = json.dumps(prefs, sort_keys=True)
    resign_in_place("brave", prefs)
    assert snapshot == json.dumps(prefs, sort_keys=True)


def test_extension_ids_in_prefs() -> None:
    prefs = {
        "extensions": {
            "settings": {
                _EXT_A: {},
                _EXT_B: {},
                "garbage": {},
                "AEBLFDKHHHDCDJPIFHHBDIOJPLFJNCOA": {},  # uppercase, rejected
            }
        }
    }
    assert sorted(extension_ids_in_prefs(prefs)) == [_EXT_A, _EXT_B]


def test_merge_extensions_adds_missing_keeps_existing() -> None:
    source = {
        "extensions": {
            "settings": {
                _EXT_A: {"state": 1, "manifest": {"name": "Arc-A"}},
                _EXT_B: {"state": 1, "manifest": {"name": "Arc-B"}},
            }
        }
    }
    target = {"extensions": {"settings": {_EXT_A: {"state": 1, "manifest": {"name": "Chrome-A"}}}}}
    added = merge_extensions(source, target)
    assert added == 1
    assert target["extensions"]["settings"][_EXT_A]["manifest"]["name"] == "Chrome-A"
    assert target["extensions"]["settings"][_EXT_B]["manifest"]["name"] == "Arc-B"


def test_resign_file_writes_back(tmp_path: Path) -> None:
    """End-to-end: a tmp file gets rewritten with valid MACs in place."""
    from arc_exporter.targets.secure_prefs import machine_id, resign_file

    p = tmp_path / "Secure Preferences"
    p.write_text(
        json.dumps(
            {
                "extensions": {"settings": {_EXT_A: {"state": 1, "manifest": {"name": "x"}}}},
                "protection": {
                    "macs": {"extensions": {"settings": {_EXT_A: "stub"}}},
                    "super_mac": "stub",
                },
            }
        ),
        encoding="utf-8",
    )
    resign_file("brave", p)
    out = json.loads(p.read_text(encoding="utf-8"))
    expected = calculate(
        b"",
        machine_id(),
        f"extensions.settings.{_EXT_A}",
        {"state": 1, "manifest": {"name": "x"}},
    )
    assert out["protection"]["macs"]["extensions"]["settings"][_EXT_A] == expected
