from __future__ import annotations

import pytest

from arc_exporter.crypto import decrypt_v10, derive_v10_key, encrypt_v10, looks_like_v10
from arc_exporter.errors import CryptoError


def test_round_trip_ascii():
    key = derive_v10_key("pw")
    pt = "correct horse battery staple"
    blob = encrypt_v10(pt, key)
    assert looks_like_v10(blob)
    assert decrypt_v10(blob, key) == pt


def test_round_trip_unicode():
    key = derive_v10_key("π")
    pt = "café crème — 🥐"
    blob = encrypt_v10(pt, key)
    assert decrypt_v10(blob, key) == pt


def test_empty_string_round_trip():
    key = derive_v10_key("pw")
    blob = encrypt_v10("", key)
    assert decrypt_v10(blob, key) == ""


def test_wrong_key_raises():
    key1 = derive_v10_key("a")
    key2 = derive_v10_key("b")
    blob = encrypt_v10("secret", key1)
    with pytest.raises(CryptoError):
        decrypt_v10(blob, key2)


def test_not_v10_blob():
    assert not looks_like_v10(b"")
    assert not looks_like_v10(b"v9garbage")
    with pytest.raises(CryptoError):
        decrypt_v10(b"v9garbage", b"\x00" * 16)


def test_derive_empty_secret_raises():
    with pytest.raises(CryptoError):
        derive_v10_key("")
