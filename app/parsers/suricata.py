"""Parser Suricata eve.json (hanya event 'alert' dan 'flow')."""
from __future__ import annotations

import json

from ..models import Event
from .common import parse_iso

# Suricata: severity 1 = paling berbahaya
_SEV = {1: "High", 2: "Medium", 3: "Low"}


def matches(rec: dict) -> bool:
    return "event_type" in rec and ("src_ip" in rec or "flow_id" in rec)


def parse(records: list[dict]) -> tuple[list[Event], int]:
    events: list[Event] = []
    invalid = 0
    for r in records:
        et = r.get("event_type")
        if et not in ("alert", "flow"):
            continue
        try:
            ts = parse_iso(r["timestamp"])
            ip = r["src_ip"]
        except (KeyError, ValueError, TypeError):
            invalid += 1
            continue
        port = r.get("dest_port")
        raw = json.dumps(r, ensure_ascii=False)
        if et == "alert":
            a = r.get("alert") or {}
            events.append(Event(
                ts=ts, src_ip=ip, source="suricata", event_type="ids_alert", raw=raw,
                dest_ip=r.get("dest_ip"), dest_port=port, signature=a.get("signature", "alert"),
                sensor_severity=_SEV.get(a.get("severity"), "Low"),
            ))
        else:
            events.append(Event(
                ts=ts, src_ip=ip, source="suricata", event_type="flow", raw=raw,
                dest_ip=r.get("dest_ip"), dest_port=port,
            ))
    return events, invalid
