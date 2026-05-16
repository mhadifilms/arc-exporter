"""Windows secret access via DPAPI + Credential Manager.

Chromium on Windows stores the encryption key inside ``Local State`` (handled in
:mod:`arc_exporter.crypto.chromium_v20`). This module covers the rare cases where we
need to read a generic credential — e.g. an Arc-side stored token.
"""

from __future__ import annotations

import sys

from arc_exporter.errors import SecretsBackendError


def get_secret(service: str) -> str | None:
    if sys.platform != "win32":
        raise SecretsBackendError("dpapi_windows backend used on non-Windows platform")
    try:
        import win32cred  # type: ignore[import-not-found]
    except ImportError as e:
        raise SecretsBackendError("pywin32 is required for the Windows credential store") from e

    try:
        cred = win32cred.CredRead(TargetName=service, Type=win32cred.CRED_TYPE_GENERIC)
    except Exception:
        return None
    blob = cred.get("CredentialBlob")
    if not blob:
        return None
    try:
        return blob.decode("utf-16-le").rstrip("\x00") if isinstance(blob, bytes) else str(blob)
    except UnicodeDecodeError:
        return blob.decode(errors="replace") if isinstance(blob, bytes) else str(blob)
