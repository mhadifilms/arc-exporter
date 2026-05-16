from __future__ import annotations

import csv
from pathlib import Path

from arc_exporter.export.cards_csv import write_cards_csv
from arc_exporter.parsers.web_data import iter_credit_cards


def test_last4_only_never_full_pan(tmp_path: Path, fake_web_data: Path, aes_key: bytes):
    out = tmp_path / "cards.csv"
    n = write_cards_csv(out, iter_credit_cards(fake_web_data), aes_key=aes_key)
    assert n == 2
    with out.open("r", encoding="utf-8") as f:
        rows = list(csv.reader(f))
    assert rows[0] == ["name_on_card", "expiration_month", "expiration_year", "last_four"]
    last4s = {r[3] for r in rows[1:]}
    assert last4s == {"1111", "0004"}
    # Make sure no full PAN appears anywhere in the file.
    raw = out.read_text(encoding="utf-8")
    assert "4111111111111111" not in raw
    assert "5500000000000004" not in raw
