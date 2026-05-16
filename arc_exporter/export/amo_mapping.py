"""Fetch Mozilla's Chrome→AMO extension mapping with a sane pagination cap."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

import httpx

_AMO_BROWSER_MAPPINGS = "https://addons.mozilla.org/api/v5/addons/browser-mappings/?browser=chrome"
_MAX_PAGES = 50  # legacy code had no cap — a misbehaving endpoint would loop forever
_TIMEOUT = httpx.Timeout(20.0, connect=10.0)


def fetch_browser_mappings(*, max_pages: int = _MAX_PAGES) -> Mapping[str, Mapping[str, str | None]]:
    """Return ``{chrome_id: {guid, slug}}``. Caps at ``max_pages`` to avoid runaway loops."""
    out: dict[str, dict[str, str | None]] = {}
    url: str | None = _AMO_BROWSER_MAPPINGS
    pages = 0
    with httpx.Client(timeout=_TIMEOUT, headers={"User-Agent": "arc-exporter/0.2"}) as client:
        while url and pages < max_pages:
            pages += 1
            resp = client.get(url)
            resp.raise_for_status()
            data = resp.json()
            for row in data.get("results", []):
                chrome_id = row.get("chrome_id") or row.get("extension_id") or row.get("external_id")
                guid = row.get("amo_guid") or row.get("guid")
                slug = row.get("amo_slug") or row.get("slug")
                if chrome_id and (guid or slug):
                    out[chrome_id] = {"guid": guid, "slug": slug}
            url = data.get("next")
    return out


def load_cached_mapping(cache_path: Path) -> Mapping[str, Mapping[str, str | None]] | None:
    if not cache_path.exists():
        return None
    try:
        return json.loads(cache_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def save_cached_mapping(cache_path: Path, mapping: Mapping[str, Mapping[str, str | None]]) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(mapping, indent=2), encoding="utf-8")


def build_policies_json(matched: list[dict]) -> dict:
    """Build a Firefox/Zen ``policies.json`` that force-installs each matched add-on."""
    settings: dict[str, dict] = {}
    for m in matched:
        slug, guid = m.get("slug"), m.get("guid")
        if not slug or not guid:
            continue
        settings[guid] = {
            "installation_mode": "force_installed",
            "install_url": f"https://addons.mozilla.org/firefox/downloads/latest/{slug}/latest.xpi",
        }
    return {"policies": {"ExtensionSettings": settings}}
