"""HTML report listing the user's Arc extensions with both Chrome WS and AMO links."""

from __future__ import annotations

import html
from collections.abc import Iterable, Mapping
from pathlib import Path

from arc_exporter.parsers.extensions import Extension
from arc_exporter.util import open_private

_HEAD = (
    "<!DOCTYPE html><html><head><meta charset='utf-8'><title>Extensions from {profile}</title>"
    "<style>body{{font-family:system-ui,sans-serif;max-width:780px;margin:24px auto;padding:0 16px;}}"
    ".ext{{margin:10px 0;padding:12px;border:1px solid #e5e5e5;border-radius:8px;}}"
    ".name{{font-weight:600;font-size:16px;}}"
    ".id{{color:#666;font-size:12px;font-family:ui-monospace,Menlo,Consolas,monospace;}}"
    ".ver{{color:#888;font-size:13px;}}"
    "a{{color:#1a73e8;text-decoration:none;}}a:hover{{text-decoration:underline;}}"
    ".missing{{color:#b00020;font-size:12px;}}"
    "</style></head><body><h1>Extensions from {profile}</h1><p>Total: {n}</p>"
)


def write_extensions_html(
    out_path: Path,
    extensions: Iterable[Extension],
    *,
    profile_name: str,
    amo_mappings: Mapping[str, Mapping[str, str | None]] | None = None,
) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    exts = sorted(extensions, key=lambda e: e.name.lower())
    parts = [_HEAD.format(profile=html.escape(profile_name, quote=True), n=len(exts))]
    for e in exts:
        chrome_url = f"https://chromewebstore.google.com/detail/{html.escape(e.chrome_id, quote=True)}"
        parts.append(
            f"<div class='ext'><div class='name'><a href='{chrome_url}' target='_blank'>{html.escape(e.name)}</a></div>"
        )
        parts.append(f"<div class='id'>{html.escape(e.chrome_id)}</div>")
        if e.version:
            parts.append(f"<div class='ver'>Version {html.escape(str(e.version))}</div>")
        if e.homepage_url:
            parts.append(
                f"<div>Homepage: <a href='{html.escape(e.homepage_url, quote=True)}' target='_blank'>{html.escape(e.homepage_url)}</a></div>"
            )
        if amo_mappings is not None:
            mapped = amo_mappings.get(e.chrome_id)
            if mapped and mapped.get("slug"):
                amo_url = f"https://addons.mozilla.org/firefox/addon/{html.escape(str(mapped['slug']), quote=True)}/"
                parts.append(f"<div>AMO: <a href='{amo_url}' target='_blank'>{amo_url}</a></div>")
            else:
                parts.append("<div class='missing'>No official AMO mapping found.</div>")
        parts.append("</div>")
    parts.append("</body></html>")
    with open_private(out_path, "w") as f:
        f.write("".join(parts))
    return len(exts)
