"""List installed extensions from a Chromium profile.

Combines three sources of truth:

- ``Preferences``: machine-readable list of extension IDs + state + manifest summary.
- ``Secure Preferences``: where Chromium *actually* stores most extension settings
  (HMAC-protected). Arc keeps its entire extensions table here; ``Preferences`` is
  usually empty. Skipping this source caused us to under-count by ~99%.
- ``Extensions/<id>/<version>/manifest.json``: real on-disk manifest, used to resolve
  localised ``__MSG_…__`` names that ``Preferences`` doesn't expand.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Extension:
    chrome_id: str
    name: str
    version: str | None = None
    homepage_url: str | None = None
    enabled: bool = True


def _extract_settings(prefs_path: Path) -> dict:
    if not prefs_path.exists():
        return {}
    try:
        prefs = json.loads(prefs_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return (prefs.get("extensions") or {}).get("settings") or {}


def from_preferences(profile_dir: Path) -> list[Extension]:
    """Read ``Preferences`` *and* ``Secure Preferences``.

    Arc registers nearly all extensions in ``Secure Preferences`` (the HMAC-protected
    file), so reading only ``Preferences`` produced a near-empty list. We merge both
    and dedupe by extension ID; entries in ``Secure Preferences`` win on conflicts
    because they carry the live state.
    """
    items: dict[str, dict] = {}
    items.update(_extract_settings(profile_dir / "Preferences"))
    items.update(_extract_settings(profile_dir / "Secure Preferences"))
    out: list[Extension] = []
    for ext_id, meta in items.items():
        if not isinstance(meta, dict) or not isinstance(ext_id, str):
            continue
        manifest = meta.get("manifest") or {}
        if "theme" in manifest:
            continue
        # Drop unrecoverable entries (component extensions, sync ghosts) that lack a
        # human name and aren't even on disk. Anything with a manifest.name or a
        # canonical 32-char extension ID is worth keeping so the user gets a real
        # picture of what was installed.
        looks_like_real = bool(manifest.get("name")) or (
            len(ext_id) == 32 and ext_id.isalpha() and ext_id.islower()
        )
        if not looks_like_real:
            continue
        state = meta.get("state")
        enabled = state in (1, True)
        name = manifest.get("name") or meta.get("path") or ext_id
        out.append(
            Extension(
                chrome_id=ext_id,
                name=str(name),
                version=manifest.get("version"),
                homepage_url=manifest.get("homepage_url"),
                enabled=bool(enabled),
            )
        )
    return out


def from_filesystem(profile_dir: Path) -> list[Extension]:
    ext_root = profile_dir / "Extensions"
    if not ext_root.is_dir():
        return []
    out: list[Extension] = []
    for ext_dir in sorted(ext_root.iterdir()):
        if not ext_dir.is_dir():
            continue
        versions = [d for d in ext_dir.iterdir() if d.is_dir()]
        if not versions:
            continue
        latest = sorted(versions, key=lambda p: p.name, reverse=True)[0]
        manifest_path = latest / "manifest.json"
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if "theme" in manifest:
            continue
        name = _resolve_i18n_name(manifest.get("name"), latest, manifest.get("default_locale"))
        out.append(
            Extension(
                chrome_id=ext_dir.name,
                name=name,
                version=manifest.get("version") or latest.name,
                homepage_url=manifest.get("homepage_url"),
                enabled=True,
            )
        )
    return out


def list_extensions(profile_dir: Path) -> list[Extension]:
    """Deduplicated union of preferences + filesystem sources, preferring filesystem names."""
    dedup: dict[str, Extension] = {}
    for ext in from_preferences(profile_dir):
        dedup[ext.chrome_id] = ext
    for ext in from_filesystem(profile_dir):
        existing = dedup.get(ext.chrome_id)
        dedup[ext.chrome_id] = Extension(
            chrome_id=ext.chrome_id,
            name=ext.name,
            version=ext.version or (existing.version if existing else None),
            homepage_url=ext.homepage_url or (existing.homepage_url if existing else None),
            enabled=existing.enabled if existing else True,
        )
    return list(dedup.values())


def _resolve_i18n_name(raw_name: str | None, ext_root: Path, default_locale: str | None) -> str:
    if not isinstance(raw_name, str) or not (raw_name.startswith("__MSG_") and raw_name.endswith("__")):
        return raw_name or ext_root.parent.name
    key = raw_name[6:-2]
    locales_dir = ext_root / "_locales"
    if not locales_dir.is_dir():
        return ext_root.parent.name
    candidates: list[Path] = []
    if default_locale and (locales_dir / default_locale / "messages.json").exists():
        candidates.append(locales_dir / default_locale / "messages.json")
    for loc in ("en-US", "en"):
        p = locales_dir / loc / "messages.json"
        if p.exists() and p not in candidates:
            candidates.append(p)
    for p in sorted(locales_dir.glob("*/messages.json")):
        if p not in candidates:
            candidates.append(p)
    for p in candidates:
        try:
            messages = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        msg = messages.get(key)
        if isinstance(msg, dict) and isinstance(msg.get("message"), str):
            return msg["message"]
    return ext_root.parent.name
