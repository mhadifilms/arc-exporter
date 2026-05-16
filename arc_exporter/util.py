"""Small pure-function utilities shared across layers.

Keep this module dependency-free (no logging, no I/O) so it stays trivially testable.
"""

from __future__ import annotations

import datetime as _dt
import os
import re
import secrets
import shutil
import string
import unicodedata
from collections.abc import Iterable
from pathlib import Path

_WINDOWS_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {f"{p}{i}" for p in ("COM", "LPT") for i in range(1, 10)}


def now_stamp() -> str:
    """A filesystem-safe timestamp computed at call time (not import time)."""
    return _dt.datetime.now().strftime("%Y%m%d-%H%M%S")


def safe_dir_name(name: str | None, *, fallback: str = "profile") -> str:
    """Make a string safe to use as a directory or file name on every supported OS.

    Replaces reserved characters with ``-``, collapses whitespace, NFC-normalises Unicode,
    and avoids Windows-reserved device names (``CON``, ``PRN``, ``AUX``, ``NUL``, ``COM1``…).
    """
    if not isinstance(name, str) or not name.strip():
        return fallback
    s = unicodedata.normalize("NFC", name).strip()
    s = re.sub(r"[\\/:*?\"<>|\x00-\x1f]+", "-", s)
    s = re.sub(r"\s+", " ", s).strip().strip(".")
    if not s:
        return fallback
    if s.upper() in _WINDOWS_RESERVED:
        s = f"{s}-"
    return s[:120]


def short_random(n: int = 6, *, alphabet: str = string.ascii_lowercase + string.digits) -> str:
    """Cryptographically random short suffix for disambiguating collisions."""
    return "".join(secrets.choice(alphabet) for _ in range(n))


def chmod_private(path: Path) -> None:
    """``chmod 0o600`` (best-effort; no-op on Windows where ACLs work differently)."""
    if os.name == "posix":
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass


def open_private(path: Path, mode: str = "w", encoding: str | None = "utf-8"):
    """Open a file with ``0o600`` permission from the moment of creation.

    On POSIX we use ``os.open`` with ``O_CREAT|O_WRONLY|O_TRUNC`` and ``0o600`` so the file
    never exists with permissive permissions. On Windows we fall back to plain ``open``;
    callers can layer additional ACL hardening if needed.
    """
    if os.name == "posix" and ("w" in mode or "x" in mode):
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        binary = "b" in mode
        fd = os.open(path, flags, 0o600)
        if binary:
            return os.fdopen(fd, mode)
        return os.fdopen(fd, mode, encoding=encoding)
    return path.open(mode, encoding=encoding) if encoding else path.open(mode)


def ensure_dir(path: Path) -> Path:
    """``mkdir -p``; returns the path so it can be chained."""
    path.mkdir(parents=True, exist_ok=True)
    return path


def file_size_human(n: int) -> str:
    """Render a byte count for display."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n / 1.0:.1f} {unit}".replace(".0 ", " ")
        n /= 1024  # type: ignore[assignment]
    return f"{n:.1f} PB"


def iter_unique(items: Iterable, *, key=lambda x: x):
    """Like :func:`set` but order-preserving and key-aware."""
    seen: set = set()
    for item in items:
        k = key(item)
        if k in seen:
            continue
        seen.add(k)
        yield item


def safe_copy_tree(src: Path, dst: Path, *, skip: Iterable[str] = (), follow_symlinks: bool = False) -> Path:
    """Copy a directory tree but skip names listed in ``skip`` and ignore dangling symlinks.

    Returns the actual destination used (may differ from ``dst`` if it already existed).
    Refuses to copy across mount-point loops via ``follow_symlinks=False`` by default.
    """
    final = dst
    if final.exists():
        # Pick the first non-colliding `dst (2)`, `dst (3)`, …
        i = 2
        while (final.parent / f"{dst.name} ({i})").exists():
            i += 1
        final = final.parent / f"{dst.name} ({i})"
    skip_set = set(skip)

    def _ignore(_dir: str, names: list[str]) -> set[str]:
        return {n for n in names if n in skip_set}

    shutil.copytree(
        src,
        final,
        symlinks=not follow_symlinks,
        ignore=_ignore,
        ignore_dangling_symlinks=True,
    )
    return final


def chromium_time_now_microseconds() -> int:
    """Chromium stores timestamps as microseconds since 1601-01-01 UTC."""
    import time as _time

    return int((_time.time() + 11644473600) * 1_000_000)


def chromium_microseconds_to_unix(ts: int | None) -> int:
    """Convert a Chromium SQLite timestamp to a POSIX time (seconds since 1970)."""
    if not ts:
        return 0
    try:
        return int((int(ts) - 11644473600000000) / 1_000_000)
    except (TypeError, ValueError):
        return 0
