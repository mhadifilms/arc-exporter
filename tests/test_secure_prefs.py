from __future__ import annotations

import hmac
import json
from pathlib import Path

from arc_exporter.targets.secure_prefs import (
    _strip_empty_children,
    calculate,
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
