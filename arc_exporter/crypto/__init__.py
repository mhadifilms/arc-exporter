"""Chromium-compatible decryption primitives.

All key derivation and AES work happens in-process via :mod:`cryptography`. Decrypted
plaintext is never written to disk. Callers are responsible for clearing buffers after
use if they care about residency.
"""

from __future__ import annotations

from arc_exporter.crypto.chromium_v10 import (
    decrypt_v10,
    derive_v10_key,
    encrypt_v10,
    looks_like_v10,
)

__all__ = [
    "decrypt_v10",
    "derive_v10_key",
    "encrypt_v10",
    "looks_like_v10",
]
