"""Typed exception hierarchy. The CLI catches :class:`ArcExporterError` to map to exit codes.

Library code must raise these — never call :func:`sys.exit`.
"""

from __future__ import annotations


class ArcExporterError(Exception):
    """Base class for every error this package raises."""

    exit_code: int = 1


class ArcNotFoundError(ArcExporterError):
    """Arc Browser is not installed at any known location."""

    exit_code = 2


class NoArcProfilesError(ArcExporterError):
    """Arc is installed but has zero user profiles."""

    exit_code = 3


class BrowserRunningError(ArcExporterError):
    """Source or target browser is currently running and ``--force`` was not passed."""

    exit_code = 4


class SecretsBackendError(ArcExporterError):
    """OS secret store (Keychain / DPAPI / libsecret) could not be reached."""

    exit_code = 5


class CryptoError(ArcExporterError):
    """A decrypt or encrypt operation failed."""

    exit_code = 6


class CorruptDataError(ArcExporterError):
    """Source data (SQLite / sidebar JSON) was malformed."""

    exit_code = 7


class TargetUnavailableError(ArcExporterError):
    """Requested target browser is not installed on this machine."""

    exit_code = 8


class ConfigError(ArcExporterError):
    """The user's config file was unreadable or invalid."""

    exit_code = 9
