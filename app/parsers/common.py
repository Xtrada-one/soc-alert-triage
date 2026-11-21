from __future__ import annotations

import json
from datetime import datetime


def parse_iso(s: str) -> datetime:
    """Ambil 'YYYY-MM-DDTHH:MM:SS' (zona waktu diabaikan agar semua sumber sebanding)."""
    return datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")


def load_json_records(lines: list[str], text: str) -> tuple[list[dict], int]:
    """Baca JSON Lines atau array JSON. Mengembalikan (records, jumlah_baris_rusak)."""
    stripped = text.lstrip()
    if stripped.startswith("["):
        try:
            arr = json.loads(stripped)
        except json.JSONDecodeError:
            return [], 1
        recs = [r for r in arr if isinstance(r, dict)]
        return recs, len(arr) - len(recs)
    recs, invalid = [], 0
    for line in lines:
        s = line.strip()
        if not s:
            continue
        try:
            rec = json.loads(s)
        except json.JSONDecodeError:
            invalid += 1
            continue
        if isinstance(rec, dict):
            recs.append(rec)
        else:
            invalid += 1
    return recs, invalid
