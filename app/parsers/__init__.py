"""Deteksi format otomatis dan normalisasi ke Event."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Event
from . import ssh, suricata, wazuh, web
from .common import load_json_records

FORMATS = ["ssh", "web", "suricata", "wazuh"]


@dataclass
class ParseResult:
    fmt: str
    events: list[Event] = field(default_factory=list)
    invalid: int = 0
    total_lines: int = 0


def detect_format(text: str) -> str:
    lines = [l for l in text.splitlines() if l.strip()]
    if not lines:
        raise ValueError("File kosong")
    first = lines[0].lstrip()
    if first.startswith("{") or first.startswith("["):
        recs, _ = load_json_records(lines[:20], text if first.startswith("[") else "")
        for rec in recs:
            if wazuh.matches(rec):
                return "wazuh"
            if suricata.matches(rec):
                return "suricata"
        raise ValueError("Format JSON tidak dikenali (didukung: Suricata eve.json, Wazuh alerts)")
    for line in lines[:20]:
        if web.matches(line):
            return "web"
        if ssh.matches(line):
            return "ssh"
    raise ValueError("Format log tidak dikenali (didukung: SSH auth.log, access log web, Suricata, Wazuh)")


def parse_text(text: str, fmt: str, year: int) -> ParseResult:
    fmt = (fmt or "auto").lower()
    if fmt == "auto":
        fmt = detect_format(text)
    if fmt not in FORMATS:
        raise ValueError(f"Format tidak didukung: {fmt}")
    lines = text.splitlines()
    total = sum(1 for l in lines if l.strip())
    if fmt == "ssh":
        events, invalid = ssh.parse(lines, year)
    elif fmt == "web":
        events, invalid = web.parse(lines)
    else:
        recs, bad = load_json_records(lines, text)
        events, invalid = (suricata.parse(recs) if fmt == "suricata" else wazuh.parse(recs))
        invalid += bad
    return ParseResult(fmt=fmt, events=events, invalid=invalid, total_lines=total)
