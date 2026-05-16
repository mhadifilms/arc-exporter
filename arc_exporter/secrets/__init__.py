"""Cross-platform access to the OS secret store.

The package picks a backend based on :data:`sys.platform`. Each backend exposes a
single function :func:`get_secret(service: str) -> str | None` that returns the
Chromium ``Safe Storage`` password (or any other named secret).

We deliberately avoid the global ``keyring`` singleton's auto-discovery because it has
historically resolved to the wrong backend inside frozen apps (PyInstaller / py2app).
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Sequence

from arc_exporter.errors import SecretsBackendError


def _get_backend() -> Callable[[str], str | None]:
    if sys.platform == "darwin":
        from arc_exporter.secrets.keychain_macos import get_secret

        return get_secret
    if sys.platform == "win32":
        from arc_exporter.secrets.dpapi_windows import get_secret

        return get_secret
    if sys.platform.startswith("linux"):
        from arc_exporter.secrets.libsecret_linux import get_secret

        return get_secret
    raise SecretsBackendError(f"no secrets backend for platform {sys.platform!r}")


_SECRETS_CACHE: dict[str, str | None] = {}
_SENTINEL_ERROR = "__SecretsBackendError__"


def get_secret(service: str) -> str | None:
    """Look up ``service`` in the OS secret store; return ``None`` if not found.

    Results are cached for the lifetime of the process so we never re-prompt the
    user for the same service. This is important on macOS where every
    ``/usr/bin/security`` invocation can trigger a permission dialog if the
    Python interpreter is not in the Keychain entry's ACL.

    Surface backend-init failures (e.g. ``security`` binary missing, pywin32 not
    installed) as :class:`SecretsBackendError`. Per-secret "not found" is just ``None``.
    """
    if service in _SECRETS_CACHE:
        cached = _SECRETS_CACHE[service]
        if cached == _SENTINEL_ERROR:
            raise SecretsBackendError(f"secrets backend failed for {service!r} (cached)")
        return cached
    backend = _get_backend()
    try:
        value = backend(service)
    except SecretsBackendError:
        _SECRETS_CACHE[service] = _SENTINEL_ERROR
        raise
    _SECRETS_CACHE[service] = value
    return value


def first_available_secret(services: Sequence[str]) -> str | None:
    """Try multiple service names (e.g. ``Arc Safe Storage`` then ``Chrome Safe Storage``).

    Returns the first non-empty hit, or ``None`` if none match.
    """
    for svc in services:
        try:
            value = get_secret(svc)
        except SecretsBackendError:
            return None
        if value:
            return value
    return None


def reset_secrets_cache() -> None:
    """Clear the in-process secrets cache (mostly useful in tests)."""
    _SECRETS_CACHE.clear()


__all__ = ["first_available_secret", "get_secret", "reset_secrets_cache"]
