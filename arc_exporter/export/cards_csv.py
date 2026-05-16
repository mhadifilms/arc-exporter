"""Write a *reference* CSV of saved credit cards.

We never export the full PAN. Output columns: ``name_on_card, expiration_month,
expiration_year, last_four`` — enough for the user to recognise each card and re-enter
it in the target browser. The PAN is decrypted **in memory only** to extract the last
four digits when ``last_four`` is empty in the source schema; it is then discarded.
"""

from __future__ import annotations

import csv
from collections.abc import Iterable
from pathlib import Path

from arc_exporter.crypto import decrypt_v10, looks_like_v10
from arc_exporter.errors import CryptoError
from arc_exporter.parsers.web_data import CardRow
from arc_exporter.util import chmod_private, open_private

HEADER = ("name_on_card", "expiration_month", "expiration_year", "last_four")


def write_cards_csv(
    out_path: Path,
    cards: Iterable[CardRow],
    *,
    aes_key: bytes | None,
) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open_private(out_path, "w") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL)
        writer.writerow(HEADER)
        for c in cards:
            last_four = c.last_four
            if not last_four and looks_like_v10(c.card_number_encrypted) and aes_key is not None:
                try:
                    pan = decrypt_v10(c.card_number_encrypted, aes_key)
                    last_four = pan[-4:] if len(pan) >= 4 else ""
                    del pan  # do not keep the full PAN
                except CryptoError:
                    last_four = ""
            writer.writerow([c.name_on_card, c.expiration_month, c.expiration_year, last_four])
            n += 1
    chmod_private(out_path)
    return n
