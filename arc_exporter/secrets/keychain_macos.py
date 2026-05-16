"""macOS Keychain access via the system ``security`` binary.

We use the binary (not the ``keyring`` library) because:

1. It is part of every macOS install and needs no Python deps.
2. It prompts the user only when access is genuinely denied — perfect for a CLI tool.
3. It avoids the ``keyring`` library's habit of picking up third-party backends inside
   frozen apps.
"""

from __future__ import annotations

import shutil
import subprocess
from typing import Final

from arc_exporter.errors import SecretsBackendError

_SECURITY_BIN: Final[str] = "/usr/bin/security"


def _which_security() -> str:
    if shutil.which(_SECURITY_BIN):
        return _SECURITY_BIN
    found = shutil.which("security")
    if not found:
        raise SecretsBackendError("`security` binary not found; is this really macOS?")
    return found


def get_secret(service: str) -> str | None:
    """Return the generic-password value for ``service`` or ``None`` if not present."""
    binary = _which_security()
    try:
        completed = subprocess.run(
            [binary, "find-generic-password", "-w", "-s", service],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError as e:
        raise SecretsBackendError(f"running `security`: {e}") from e
    if completed.returncode != 0:
        return None
    value = completed.stdout.strip()
    return value or None
