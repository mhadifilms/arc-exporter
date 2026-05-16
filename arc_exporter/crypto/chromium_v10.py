"""Chromium-style ``v10`` AES-128-CBC encryption/decryption.

Chromium on macOS and Linux uses this scheme for ``Login Data``, credit cards, and (older)
cookies::

    key  = PBKDF2(HMAC-SHA1, password, "saltysalt", 1003, dkLen=16)
    iv   = b" " * 16
    blob = b"v10" + AES-128-CBC(plaintext, key, iv, PKCS#7)

The old implementation shelled out to the ``openssl`` CLI through a deleted temp file,
which briefly placed plaintext credentials on disk. This module performs everything in
memory.
"""

from __future__ import annotations

import hashlib
from typing import Final

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from arc_exporter.errors import CryptoError

_SALT: Final[bytes] = b"saltysalt"
_ITERATIONS: Final[int] = 1003
_KEY_LEN: Final[int] = 16
_IV: Final[bytes] = b" " * 16
_PREFIX: Final[bytes] = b"v10"


def derive_v10_key(secret: str | bytes) -> bytes:
    """Derive the AES-128 key from the Chromium ``Safe Storage`` keychain secret.

    Empty / missing secrets raise :class:`CryptoError` instead of silently returning a
    deterministic-but-wrong key.
    """
    if not secret:
        raise CryptoError("empty Chromium Safe Storage secret")
    pw = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
    return hashlib.pbkdf2_hmac("sha1", pw, _SALT, _ITERATIONS, dklen=_KEY_LEN)


def looks_like_v10(blob: bytes | bytearray | memoryview | None) -> bool:
    """Return ``True`` iff ``blob`` is a Chromium ``v10``-prefixed ciphertext."""
    if not isinstance(blob, (bytes, bytearray, memoryview)):
        return False
    return len(blob) >= 3 + 16 and bytes(blob[:3]) == _PREFIX


def decrypt_v10(blob: bytes | bytearray | memoryview, key: bytes) -> str:
    """Decrypt a ``v10``-prefixed ciphertext. Returns plaintext as UTF-8 string.

    Raises :class:`CryptoError` if the input is not a valid ``v10`` blob, or the AES
    decryption fails. PKCS#7 padding errors raise :class:`CryptoError` rather than the
    underlying :class:`ValueError`.
    """
    if not looks_like_v10(blob):
        raise CryptoError("not a v10 blob")
    ct = bytes(blob[3:])
    if len(ct) % 16:
        raise CryptoError("v10 ciphertext length is not a multiple of 16")
    cipher = Cipher(algorithms.AES(key), modes.CBC(_IV))
    dec = cipher.decryptor()
    padded = dec.update(ct) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    try:
        pt = unpadder.update(padded) + unpadder.finalize()
    except ValueError as e:
        raise CryptoError(f"v10 padding error: {e}") from e
    try:
        return pt.decode("utf-8")
    except UnicodeDecodeError:
        return pt.decode("utf-8", errors="replace")


def encrypt_v10(plaintext: str | bytes, key: bytes) -> bytes:
    """Encrypt ``plaintext`` into a Chromium ``v10`` blob ready to insert into ``Login Data``."""
    data = plaintext.encode("utf-8") if isinstance(plaintext, str) else bytes(plaintext)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(_IV))
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    return _PREFIX + ct
