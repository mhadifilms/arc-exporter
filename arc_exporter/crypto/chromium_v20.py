"""Chromium v20 / "App-Bound Encryption" key unwrap (Windows-only).

Recent Chrome versions on Windows store a *wrapped* AES-256-GCM key inside
``Local State`` under ``os_crypt.app_bound_encrypted_key``. The wrapping uses DPAPI
("LocalMachine" or "CurrentUser" depending on version) plus an AES-GCM layer keyed by
the Chrome process itself.

We currently support the v10-on-Windows mode (DPAPI-wrapped 32-byte key, then AES-GCM
record-by-record). True v20 unwrapping requires injecting into the Chrome process and
is intentionally **not** implemented here — it would void the safety guarantees the rest
of this package provides. When we encounter a v20 cookie we surface a clear, actionable
error.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Final

from arc_exporter.errors import CryptoError

_V10_PREFIX: Final[bytes] = b"v10"
_V20_PREFIX: Final[bytes] = b"v20"


def is_supported_platform() -> bool:
    """Only Windows uses v10/v20 AES-GCM blobs (macOS/Linux use the v10 CBC scheme)."""
    return sys.platform == "win32"


def load_master_key_from_local_state(local_state_path: Path) -> bytes:
    """Return the 32-byte AES-256 master key Chromium stored in ``Local State``.

    Raises :class:`CryptoError` if the file is missing or the key cannot be unwrapped.
    Callers on non-Windows platforms should never reach this function.
    """
    if not is_supported_platform():
        raise CryptoError("Chromium v20 key unwrap is only supported on Windows")
    try:
        with local_state_path.open("r", encoding="utf-8") as f:
            ls = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        raise CryptoError(f"could not read Local State: {e}") from e

    os_crypt = ls.get("os_crypt") or {}
    enc_b64 = os_crypt.get("encrypted_key")
    if not enc_b64:
        raise CryptoError("Local State has no os_crypt.encrypted_key")
    try:
        wrapped = base64.b64decode(enc_b64)
    except (ValueError, TypeError) as e:
        raise CryptoError(f"encrypted_key is not valid base64: {e}") from e
    if not wrapped.startswith(b"DPAPI"):
        raise CryptoError("encrypted_key missing DPAPI prefix; possibly v20 / App-Bound")
    try:
        import win32crypt  # type: ignore[import-not-found]
    except ImportError as e:
        raise CryptoError("pywin32 is required to unwrap the Windows master key") from e

    try:
        _desc, key = win32crypt.CryptUnprotectData(wrapped[len(b"DPAPI") :], None, None, None, 0)
    except Exception as e:  # win32 errors aren't a stable subclass
        raise CryptoError(f"DPAPI unwrap failed: {e}") from e
    if len(key) != 32:
        raise CryptoError(f"unexpected master-key length {len(key)}; expected 32")
    return key


def decrypt_aes_gcm_record(blob: bytes, master_key: bytes) -> str:
    """Decrypt a single Chromium v10-on-Windows AES-GCM ciphertext record.

    Layout: ``b"v10" || nonce(12) || ciphertext || tag(16)``.
    """
    if not blob.startswith(_V10_PREFIX):
        if blob.startswith(_V20_PREFIX):
            raise CryptoError(
                "v20 ciphertext requires App-Bound Encryption unwrap (Chrome process); "
                "not implemented in arc-exporter"
            )
        raise CryptoError("unrecognised ciphertext prefix")
    body = blob[len(_V10_PREFIX) :]
    if len(body) < 12 + 16:
        raise CryptoError("AES-GCM record too short")
    nonce, rest = body[:12], body[12:]
    ciphertext, tag = rest[:-16], rest[-16:]
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as e:  # pragma: no cover - cryptography is mandatory
        raise CryptoError("cryptography package missing") from e
    aes = AESGCM(master_key)
    try:
        pt = aes.decrypt(nonce, ciphertext + tag, associated_data=None)
    except Exception as e:
        raise CryptoError(f"AES-GCM decrypt failed: {e}") from e
    return pt.decode("utf-8", errors="replace")
