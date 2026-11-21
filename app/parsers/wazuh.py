"""Parser alert Wazuh (alerts.json)."""
from __future__ import annotations

import json

from ..models import Event
from .common import parse_iso


def matches(rec: dict) -> bool:
    return isinstance(rec.get("rule"), dict) and "level" in rec["rule"]


def _severity(level: int) -> str | None:
    if level >= 12:
        return "Critical"
    if level >= 10:
        return "High"
    if level >= 7:
        return "Medium"
    if level >= 5:
        return "Low"
    return None  # level rendah dianggap informasi, bukan alert


def parse(records: list[dict]) -> tuple[list[Event], int]:
    events: list[Event] = []
    invalid = 0
    for r in records:
        try:
            ts = parse_iso(r["timestamp"])
            rule = r["rule"]
            level = int(rule["level"])
        except (KeyError, ValueError, TypeError):
            invalid += 1
            continue
        sev = _severity(level)
        if sev is None:
            continue
        data = r.get("data") or {}
        agent = r.get("agent") or {}
        ip = data.get("srcip") or data.get("src_ip") or agent.get("name") or "unknown"
        mitre = (rule.get("mitre") or {}).get("id") or []
        events.append(Event(
            ts=ts, src_ip=str(ip), source="wazuh", event_type="wazuh_alert",
            raw=json.dumps(r, ensure_ascii=False), signature=rule.get("description", "wazuh alert"),
            sensor_severity=sev, mitre=list(mitre),
        ))
    return events, invalid
