"""arc_exporter — safely migrate Arc Browser profiles into other browsers.

The package is intentionally organised into small, testable layers:

- ``arc_exporter.crypto``   Chromium v10 / v20 AES key handling (no temp files).
- ``arc_exporter.secrets``  per-OS secret store access (Keychain / DPAPI / libsecret).
- ``arc_exporter.guards``   safety checks (browsers running, disk space, backups).
- ``arc_exporter.source``   reading Arc profiles on macOS / Windows.
- ``arc_exporter.parsers``  Chromium SQLite + Arc StorableSidebar.json parsers.
- ``arc_exporter.export``   portable artefact writers (HTML, CSV, JSON, SQLite, Markdown).
- ``arc_exporter.targets``  per-target-browser writers using the same primitives.
- ``arc_exporter.cli``      typer-powered CLI surface.

Nothing in this package may call :func:`sys.exit` or :func:`print` directly except the
top-level CLI module.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.2.0"
