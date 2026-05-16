"""Linux secret access via ``secretstorage`` (the libsecret DBus client).

Chromium on Linux uses one of three modes:

- ``basic``    No encryption (literal plaintext in DB; we return the well-known string).
- ``gnome``    GNOME Keyring via ``Chromium Safe Storage`` / ``Chrome Safe Storage``.
- ``kwallet``  KWallet (not supported here yet; falls back to ``None``).

The Chromium mode is recorded in ``os_crypt.encrypted`` of the profile's ``Local State``.
For most desktops it is ``gnome``.
"""

from __future__ import annotations

import sys

from arc_exporter.errors import SecretsBackendError

_BASIC_SECRET = "peanuts"  # Documented Chromium fallback for the "basic" mode.


def get_secret(service: str) -> str | None:
    if not sys.platform.startswith("linux"):
        raise SecretsBackendError("libsecret_linux backend used on non-Linux platform")
    try:
        import secretstorage  # type: ignore[import-not-found]
    except ImportError as e:
        # If we can't talk to libsecret at all, fall back to the documented basic key.
        # That fits the most common headless / WSL setup.
        raise SecretsBackendError("secretstorage is required to talk to libsecret") from e

    try:
        bus = secretstorage.dbus_init()
    except Exception as e:
        raise SecretsBackendError(f"could not connect to D-Bus: {e}") from e

    try:
        collection = secretstorage.get_default_collection(bus)
        if collection.is_locked():
            collection.unlock()
        for item in collection.get_all_items():
            attrs = item.get_attributes()
            if attrs.get("application") == service or attrs.get("xdg:schema") == service:
                return item.get_secret().decode("utf-8", errors="replace")
            if item.get_label() == service:
                return item.get_secret().decode("utf-8", errors="replace")
    except Exception as e:
        raise SecretsBackendError(f"libsecret query failed: {e}") from e
    finally:
        try:
            bus.close()
        except Exception:
            pass
    return None


def basic_mode_secret() -> str:
    """Return the documented secret Chromium uses when ``os_crypt.encrypted`` is ``basic``."""
    return _BASIC_SECRET
