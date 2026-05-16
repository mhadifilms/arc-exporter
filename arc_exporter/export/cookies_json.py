"""Write cookies as JSON (one record per cookie). Useful for ``cookies.txt`` tooling."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from arc_exporter.crypto import decrypt_v10, looks_like_v10
from arc_exporter.errors import CryptoError
from arc_exporter.parsers.cookies import CookieRow
from arc_exporter.util import chmod_private, chromium_microseconds_to_unix, open_private


def write_cookies_json(
    out_path: Path,
    cookies: Iterable[CookieRow],
    *,
    aes_key: bytes | None,
) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    payload: list[dict] = []
    for c in cookies:
        value = c.value
        if not value and c.encrypted_value and aes_key is not None and looks_like_v10(c.encrypted_value):
            try:
                value = decrypt_v10(c.encrypted_value, aes_key)
            except CryptoError:
                value = ""
        payload.append(
            {
                "host": c.host,
                "name": c.name,
                "value": value,
                "path": c.path,
                "expires": chromium_microseconds_to_unix(c.expires_utc),
                "secure": c.is_secure,
                "http_only": c.is_httponly,
                "same_site": c.samesite,
            }
        )
    with open_private(out_path, "w") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    chmod_private(out_path)
    return len(payload)
