"""Re-sign Chromium's ``Secure Preferences`` file for the current machine.

Chromium's HMAC-protected preferences store is keyed by:

* a per-vendor *seed* baked into the binary (the 64-byte ``IDR_PREF_HASH_SEED_BIN``
  blob for Google Chrome; the empty string for Brave/Edge/Opera/Vivaldi/etc.), and
* a *device ID* derived from the host — ``IOPlatformUUID`` on macOS, the user's SID
  (minus the relative ID) on Windows, and the empty string on Linux.

When a profile is copied between machines or between browsers, the existing HMACs
no longer match because either the seed or the device ID (usually both) differ.
Chromium then quietly resets every tracked preference whose HMAC fails, which is
why a naive copy of Arc's ``Secure Preferences`` results in zero extensions: the
``extensions.settings`` sub-tree is "tampered with", so Chrome wipes it and the
matching ``Extensions/<id>/`` folders are garbage-collected on the next launch.

This module ports the algorithm so we can rewrite ``protection.macs`` and
``protection.super_mac`` for the target browser running on the current machine.
The HMAC and JSON-canonicalisation routines are mechanical translations of
``services/preferences/tracked/pref_hash_calculator.cc`` and the per-OS device-ID
helpers under the same directory. A standalone Python reference for the same
algorithm appears at https://gist.github.com/0xdevalias/e95b914b1e0e464bbb847c914d0cf8c8;
the academic background is documented in *HMAC and "Secure Preferences":
Revisiting Chromium-based Browsers Security* (Picazo-Sanchez, Schneider,
Sabelfeld, CANS 2020).

This is **not** a security exploit. We re-sign a file for the same user on the
same machine; Chromium itself does this on every save. The only thing that's
"unusual" about our use is that we're handing the new copy a pre-populated
``extensions.settings`` table.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import json
import logging
import plistlib
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

log = logging.getLogger("arc_exporter.targets.secure_prefs")

# Chrome 137+ added a second protection layer on top of the legacy HMAC: every
# tracked-pref entry gets a sibling ``<name>_encrypted_hash`` that holds an
# OSCrypt-encrypted SHA256 of (seed + path + canonical value). When the value
# changes Chrome validates BOTH the HMAC and the encrypted hash; mismatch on
# either side causes Chrome to silently wipe the entry. Implemented in
# ``services/preferences/tracked/pref_hash_calculator.cc`` (CalculateEncryptedHash)
# and ``components/os_crypt/sync/os_crypt_mac.mm`` (EncryptString). The macOS
# OSCrypt format is:
#
#   v10 (3 bytes prefix) || AES-128-CBC( SHA256(message), key, IV=" "*16, PKCS7 )
#
# The key is the same 16-byte PBKDF2 output we derive for cookies / Login Data
# re-encryption (``derive_v10_key`` in ``arc_exporter.crypto``).
_OSCRYPT_IV = b" " * 16
_OSCRYPT_PREFIX = b"v10"
_ENCRYPTED_HASH_SUFFIX = "_encrypted_hash"

# ---------------------------------------------------------------------------
# Seeds. Sourced from ``chrome/browser/prefs/chrome_pref_service_factory.cc``
# (`IDR_PREF_HASH_SEED_BIN` when ``GOOGLE_CHROME_BRANDING`` is defined, otherwise
# the empty string). The Chrome blob is loaded from the non-public file
# ``resources/settings_internal/pref_hash_seed.bin`` shipped with each release.
# As of 2026-03 (cf. ``0xdevalias`` gist) the value has been stable since at
# least 2014; the Chromium tree has no rotation logic for it. We treat every
# Chromium fork that ships without GOOGLE_CHROME_BRANDING as having the empty
# seed, which matches the Picazo-Sanchez et al. paper's brute-force findings
# for Brave, Edge, and Opera.
# ---------------------------------------------------------------------------

_CHROME_SEED_HEX = (
    "e748f336d85ea5f9dcdf25d8f347a65b4cdf667600f02df6724a2af18a212d26"
    "b788a25086910cf3a90313696871f3dc05823730c91df8ba5c4fd9c884b505a8"
)

_SEEDS: dict[str, bytes] = {
    "chrome": bytes.fromhex(_CHROME_SEED_HEX),
    # Every other Chromium fork ships with seed = "".
    "brave": b"",
    "edge": b"",
    "vivaldi": b"",
    "opera": b"",
    "dia": b"",
    "comet": b"",
    "sidekick": b"",
    "arc-search": b"",
}


def seed_for(target_name: str) -> bytes:
    """Return the HMAC seed for ``target_name``.

    Unknown targets default to the empty seed, which is what every non-Google
    Chromium-branded build uses. That's safer than guessing the Chrome blob —
    a wrong seed simply produces invalid HMACs that Chromium will reset rather
    than crash on.
    """
    return _SEEDS.get(target_name, b"")


# ---------------------------------------------------------------------------
# Device ID. Mirrors ``services/preferences/tracked/device_id_{mac,win,linux}.cc``.
# ---------------------------------------------------------------------------


@functools.cache
def machine_id() -> str:
    """Return the device ID this Chromium build uses for HMAC computation.

    macOS: ``IOPlatformUUID`` from ``IOPlatformExpertDevice``. We shell out to
    ``ioreg`` rather than calling the C API because the C extension would add
    a hard PyObjC dependency for a value we read once per migration.

    Windows: the user's SID with the relative-ID (last ``-NNNN`` component)
    stripped. ``whoami /user /fo csv /nh`` is the cheapest way to read it
    without an extra dependency.

    Linux: empty string. Chromium has no Linux device-ID implementation —
    ``device_id_unittest.cc`` shows the platform path falls through to
    ``MachineIdStatus::NOT_IMPLEMENTED`` and the resulting ID is ``""``.
    """
    if sys.platform == "darwin":
        try:
            xml = subprocess.check_output(
                ["ioreg", "-c", "IOPlatformExpertDevice", "-d", "1", "-r", "-a"],
                stderr=subprocess.DEVNULL,
            )
            data = plistlib.loads(xml)
            return str(data[0]["IOPlatformUUID"])
        except (OSError, subprocess.CalledProcessError, KeyError, ValueError) as e:
            log.warning("could not read IOPlatformUUID, falling back to empty device_id: %s", e)
            return ""
    if sys.platform == "win32":
        try:
            out = subprocess.check_output(
                ["whoami", "/user", "/fo", "csv", "/nh"],
                stderr=subprocess.DEVNULL,
                text=True,
            ).strip()
            # CSV form: "DOMAIN\\user","S-1-5-21-...-1234"
            parts = [p.strip('"') for p in out.split(",")]
            if len(parts) >= 2:
                sid = parts[1]
                # Drop the trailing relative ID per ``device_id_win.cc``.
                return sid.rsplit("-", 1)[0]
        except (OSError, subprocess.CalledProcessError) as e:
            log.warning("could not read SID, falling back to empty device_id: %s", e)
        return ""
    return ""


# ---------------------------------------------------------------------------
# JSON canonicalisation. This must match ``base::WriteJson`` *byte for byte*
# because every difference would produce a different HMAC and Chromium would
# treat the pref as tampered.
#
# The rules, in order:
#   1. Strip empty dicts / lists recursively from dict-shaped values (lists are
#      passed through; only dicts get the strip pass).
#   2. Serialise with no whitespace, comma + colon separators only.
#   3. Escape ``<`` as ``\u003C`` (Chrome's HTML safety), plus ``\u2028`` /
#      ``\u2029`` line separators, plus the standard JSON escapes for control
#      characters and quote/backslash.
#   4. Floats that look like integers get ``.0`` appended (Chrome's writer is
#      explicit about distinguishing real numbers from ints in serialised form).
# ---------------------------------------------------------------------------


def _strip_empty_children(value: Any) -> Any:
    """Recursive port of ``RemoveEmptyValueDictEntries`` from Chromium.

    Returns ``None`` for dicts / lists that end up empty after stripping; the
    caller then drops the matching key. Scalars are returned unchanged.
    """
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            stripped = _strip_empty_children(v)
            if stripped is None:
                continue
            out[k] = stripped
        return out if out else None
    if isinstance(value, list):
        out_list: list[Any] = []
        for item in value:
            stripped = _strip_empty_children(item)
            if stripped is None:
                continue
            out_list.append(stripped)
        return out_list if out_list else None
    return value


# Characters that get special escapes in Chromium's JSON writer. Anything not in
# this table that has codepoint < 32 gets ``\u00xx``; everything else passes
# through verbatim (Chromium does *not* escape non-ASCII codepoints — Python's
# default ``json`` does, which is why we hand-roll the serialiser).
_SPECIAL_ESCAPES = {
    "\b": "\\b",
    "\f": "\\f",
    "\n": "\\n",
    "\r": "\\r",
    "\t": "\\t",
    "\\": "\\\\",
    '"': '\\"',
    "<": "\\u003C",
    "\u2028": "\\u2028",
    "\u2029": "\\u2029",
}


def _encode_string(s: str) -> bytes:
    out: list[str] = ['"']
    for c in s:
        special = _SPECIAL_ESCAPES.get(c)
        if special is not None:
            out.append(special)
        elif ord(c) < 32:
            out.append(f"\\u00{ord(c):02x}")
        else:
            out.append(c)
    out.append('"')
    return "".join(out).encode("utf-8")


def chrome_json(value: Any) -> bytes:
    """Serialise ``value`` exactly the way Chromium's ``JSONStringValueSerializer`` does."""
    if value is None:
        return b"null"
    if isinstance(value, bool):
        return b"true" if value else b"false"
    if isinstance(value, int):
        return str(value).encode("ascii")
    if isinstance(value, float):
        text = repr(value)
        # Chrome's NumberToString always renders floats with a decimal point so
        # the parser can distinguish them from ints on round-trip.
        if "." not in text and "e" not in text and "E" not in text:
            text += ".0"
        return text.encode("ascii")
    if isinstance(value, str):
        return _encode_string(value)
    if isinstance(value, list):
        parts = b",".join(chrome_json(v) for v in value)
        return b"[" + parts + b"]"
    if isinstance(value, dict):
        parts = b",".join(
            _encode_string(str(k)) + b":" + chrome_json(v) for k, v in value.items()
        )
        return b"{" + parts + b"}"
    raise TypeError(f"chrome_json does not support {type(value).__name__}")


def value_as_string(value: Any) -> bytes:
    """Port of ``ValueAsString`` in ``pref_hash_calculator.cc``."""
    if isinstance(value, dict):
        stripped = _strip_empty_children(value) or {}
        return chrome_json(stripped)
    return chrome_json(value)


# ---------------------------------------------------------------------------
# HMAC and resigning.
# ---------------------------------------------------------------------------


def calculate(seed: bytes, device_id: str, path: str, value: Any) -> str:
    """``HMAC-SHA256(seed, device_id + path + canonical_value)`` as upper-case hex."""
    import hmac as _hmac

    msg = device_id.encode("utf-8") + path.encode("utf-8") + value_as_string(value)
    return _hmac.new(seed, msg, "sha256").hexdigest().upper()


def calculate_encrypted(seed: bytes, aes_key: bytes, path: str, value: Any) -> str:
    """OSCrypt-encrypted SHA256 hash of ``(seed || path || canonical_value)``.

    This is the second protection layer Chrome 137+ writes alongside the
    legacy HMAC. Without it, modifying any value and updating only the HMAC
    causes Chrome to wipe the entry (because the stored encrypted hash no
    longer matches the new value — diagnosed empirically against Chrome
    148 on macOS: ``Profile 2`` lost all 11 freshly-installed extensions on
    next launch because we updated MACs but not encrypted hashes).

    Algorithm (mechanical translation of
    ``PrefHashCalculator::CalculateEncryptedHash`` in
    ``services/preferences/tracked/pref_hash_calculator.cc``, combined
    with ``OSCryptImpl::EncryptString`` in
    ``components/os_crypt/sync/os_crypt_mac.mm``)::

        message    = seed || path || value_as_string(value)
        digest     = SHA256(message)                          # 32 bytes
        ciphertext = AES-128-CBC( digest, key, IV=" "*16,     # 48 bytes
                                  PKCS7 padded )
        blob       = b"v10" || ciphertext                     # 51 bytes
        result     = base64(blob)                             # 68 chars

    ``aes_key`` is the destination browser's Safe Storage key: the same
    16-byte ``PBKDF2(keychain_password, "saltysalt", 1003, 16)`` we derive
    for cookies / Login Data / Web Data re-encryption. Linux and Windows
    Chromium use slightly different ``OSCrypt::EncryptString`` schemes
    (AES-GCM with a random nonce, DPAPI on Windows); this implementation
    is macOS-only. Calling sites already gate on
    ``sys.platform == "darwin"`` before reaching here.
    """
    msg = seed + path.encode("utf-8") + value_as_string(value)
    digest = hashlib.sha256(msg).digest()
    padder = padding.PKCS7(128).padder()
    padded = padder.update(digest) + padder.finalize()
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(_OSCRYPT_IV))
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    return base64.b64encode(_OSCRYPT_PREFIX + ct).decode("ascii")


def _resign_macs(
    seed: bytes,
    device_id: str,
    parent_keys: list[str],
    macs_subtree: dict[str, Any],
    prefs_subtree: Mapping[str, Any],
    encrypt_key: bytes | None,
    in_encrypted_mode: bool = False,
) -> None:
    """Recompute every leaf MAC and encrypted hash under ``macs_subtree``.

    Walks the existing ``protection.macs`` tree as a template — Chromium
    decides which prefs are tracked atomically vs. split-by-child, and the
    shape of the MAC tree captures that decision. We only touch leaves we
    already see; any extension whose MAC entry was missing in Arc stays
    missing in the target, and any pref that exists in the data but has
    no MAC entry is left alone.

    Encrypted-hash siblings (``<name>_encrypted_hash``) live at the same
    level as their legacy-HMAC counterparts. Both compute over the SAME
    underlying pref value at the SAME pref path (e.g.
    ``extensions.settings.<id>``) — only the algorithm differs. We detect
    these by suffix at the entry point, strip the suffix to recover the
    real pref path, and pass an ``in_encrypted_mode`` flag down through
    any nested split-MAC dicts so deeper leaves are computed as encrypted
    hashes too.

    If ``encrypt_key`` is ``None`` we silently skip encrypted-hash entries
    rather than break a migration that doesn't have Safe Storage access
    (e.g. dry-run, headless CI). The legacy HMACs still get rewritten,
    which is enough for older Chrome builds; only Chrome 137+ requires
    the encrypted hash, and only on macOS.
    """
    for key in sorted(macs_subtree.keys()):
        is_encrypted_root = (
            not in_encrypted_mode
            and isinstance(key, str)
            and key.endswith(_ENCRYPTED_HASH_SUFFIX)
        )
        # Encrypted-hash entries reference their LEGACY sibling for both
        # the pref path component and the value to hash. Strip the suffix
        # to recover the legacy name.
        prefs_key = (
            key[: -len(_ENCRYPTED_HASH_SUFFIX)] if is_encrypted_root else key
        )
        if prefs_key not in prefs_subtree:
            continue
        node = macs_subtree[key]
        sub_prefs = prefs_subtree[prefs_key]
        next_encrypted = in_encrypted_mode or is_encrypted_root

        if isinstance(node, dict):
            _resign_macs(
                seed,
                device_id,
                parent_keys + [prefs_key],
                node,
                sub_prefs if isinstance(sub_prefs, Mapping) else {},
                encrypt_key,
                next_encrypted,
            )
        elif isinstance(node, str):
            path = ".".join(parent_keys + [prefs_key])
            if next_encrypted:
                if encrypt_key is not None:
                    macs_subtree[key] = calculate_encrypted(
                        seed, encrypt_key, path, sub_prefs
                    )
                # else: leave the stale encrypted hash in place. Chrome
                # may still accept the entry on builds where the
                # encrypted-hash validation hasn't shipped yet.
            else:
                macs_subtree[key] = calculate(seed, device_id, path, sub_prefs)
        # Any other type (None, list, int…) is a malformed MAC entry —
        # leave it alone so Chromium logs a corruption warning rather
        # than silently accepting our garbage.


def resign_in_place(
    target_name: str,
    prefs: dict[str, Any],
    *,
    target_aes_key: bytes | None = None,
) -> None:
    """Rewrite ``prefs['protection']['macs']`` and ``super_mac`` for ``target_name``.

    Mutates ``prefs``. No-op if the protection block is missing (some forks /
    older profiles store everything in the unprotected ``Preferences`` instead).

    ``target_aes_key`` is the destination browser's 16-byte Safe Storage key
    (PBKDF2 output we derive for cookie / Login Data re-encryption). It's
    required to compute the Chrome 137+ ``_encrypted_hash`` entries; pass
    ``None`` and the resign covers the legacy HMACs only.
    """
    seed = seed_for(target_name)
    device_id = machine_id()
    protection = prefs.get("protection")
    if not isinstance(protection, dict):
        return
    macs = protection.get("macs")
    if isinstance(macs, dict):
        _resign_macs(seed, device_id, [], macs, prefs, target_aes_key)
    if "super_mac" in protection and isinstance(macs, dict):
        # super_mac is HMAC over the (now-recomputed) macs dict, with the empty
        # string as the pref path. The macs dict is *not* stripped of empty
        # children by Chromium for this calculation — but since we just wrote
        # it ourselves it has no empty children anyway.
        protection["super_mac"] = calculate(seed, device_id, "", macs)


def resign_file(
    target_name: str,
    path: Path,
    *,
    target_aes_key: bytes | None = None,
) -> None:
    """Convenience wrapper: read JSON, resign, write back atomically."""
    data = json.loads(path.read_text(encoding="utf-8"))
    resign_in_place(target_name, data, target_aes_key=target_aes_key)
    # Write with the same compact format Chromium itself uses (no whitespace).
    text = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    tmp = path.with_suffix(path.suffix + ".arc-exporter-tmp")
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(path)


# ---------------------------------------------------------------------------
# Convenience: pulling out and merging the ``extensions`` sub-tree.
# ---------------------------------------------------------------------------


def extension_ids_in_prefs(prefs: Mapping[str, Any]) -> list[str]:
    """Return every 32-char extension ID found in ``extensions.settings``."""
    settings = prefs.get("extensions", {}).get("settings", {})
    if not isinstance(settings, Mapping):
        return []
    return [k for k in settings if _looks_like_extension_id(k)]


def merge_extensions(
    source_prefs: Mapping[str, Any],
    target_prefs: dict[str, Any],
    *,
    overwrite: bool = False,
) -> int:
    """Merge ``source_prefs['extensions']['settings']`` into ``target_prefs``.

    Returns the number of extension entries added. Existing entries in
    ``target_prefs`` are kept by default (so the target's preinstalled extensions
    aren't clobbered); pass ``overwrite=True`` to favour the source.

    Also copies the matching ``protection.macs.extensions.settings.<id>`` entries
    so the resign pass has something to recompute — the MAC values themselves
    are placeholders that will be overwritten by the resign pass that follows.
    """
    src_ext = source_prefs.get("extensions", {})
    if not isinstance(src_ext, Mapping):
        return 0
    src_settings = src_ext.get("settings", {})
    if not isinstance(src_settings, Mapping):
        return 0

    target_ext = target_prefs.setdefault("extensions", {})
    target_settings = target_ext.setdefault("settings", {})
    target_macs = (
        target_prefs.setdefault("protection", {})
        .setdefault("macs", {})
        .setdefault("extensions", {})
        .setdefault("settings", {})
    )
    src_macs = (
        source_prefs.get("protection", {})
        .get("macs", {})
        .get("extensions", {})
        .get("settings", {})
    )

    added = 0
    for ext_id, value in src_settings.items():
        if not _looks_like_extension_id(ext_id):
            continue
        if not overwrite and ext_id in target_settings:
            continue
        target_settings[ext_id] = value
        # Placeholder; will be recomputed by resign_in_place. Reuse the source
        # mac if present so the resign pass has the right pref path to hash.
        target_macs[ext_id] = src_macs.get(ext_id, "")
        added += 1
    return added


def _looks_like_extension_id(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 32
        and value.isalpha()
        and value.islower()
        and all("a" <= c <= "p" for c in value)
    )


# ---------------------------------------------------------------------------
# Re-export only the public surface.
# ---------------------------------------------------------------------------

__all__ = (
    "calculate",
    "calculate_encrypted",
    "chrome_json",
    "extension_ids_in_prefs",
    "machine_id",
    "merge_extensions",
    "resign_file",
    "resign_in_place",
    "seed_for",
    "value_as_string",
)
