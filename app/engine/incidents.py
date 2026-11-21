"""Pengelompokan alert menjadi insiden per IP, plus data timeline untuk dashboard."""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta

from ..models import SEVERITIES, SEVERITY_ORDER


def _incident_status(statuses: set[str]) -> str:
    if statuses == {"False Positive"}:
        return "False Positive"
    if "True Positive" in statuses:
        return "True Positive"
    if "Investigating" in statuses:
        return "Investigating"
    return "New"


def build_incidents(alerts: list[dict]) -> list[dict]:
    groups: dict[str, list[dict]] = defaultdict(list)
    for a in alerts:
        groups[a["src_ip"]].append(a)
    out = []
    for ip, als in groups.items():
        als = sorted(als, key=lambda a: (-a["score"], SEVERITY_ORDER[a["severity"]]))
        recs: list[str] = []
        for a in als:
            if a["recommendation"] and a["recommendation"] not in recs:
                recs.append(a["recommendation"])
        out.append({
            "src_ip": ip,
            "severity": min((a["severity"] for a in als), key=SEVERITY_ORDER.get),
            "score": max(a["score"] for a in als),
            "correlated": any(a["correlated"] for a in als),
            "alert_count": len(als),
            "rules": [{"id": a["rule_id"], "name": a["rule_name"]} for a in als],
            "mitre": sorted({m for a in als for m in a["mitre"]}),
            "first_seen": min(a["first_seen"] for a in als),
            "last_seen": max(a["last_seen"] for a in als),
            "status": _incident_status({a["status"] for a in als}),
            "recommendations": recs,
            "alerts": als,
        })
    out.sort(key=lambda i: (-i["score"], SEVERITY_ORDER[i["severity"]], i["first_seen"]))
    return out


def build_timeline(alerts: list[dict]) -> dict:
    """Jumlah alert per severity per bucket waktu (berdasarkan first_seen)."""
    if not alerts:
        return {"bucket": "menit", "points": []}
    times = [datetime.fromisoformat(a["first_seen"]) for a in alerts]
    span = max(times) - min(times)
    if span <= timedelta(hours=3):
        name, step = "menit", timedelta(minutes=1)
        floor = lambda d: d.replace(second=0, microsecond=0)
    elif span <= timedelta(days=3):
        name, step = "jam", timedelta(hours=1)
        floor = lambda d: d.replace(minute=0, second=0, microsecond=0)
    else:
        name, step = "hari", timedelta(days=1)
        floor = lambda d: d.replace(hour=0, minute=0, second=0, microsecond=0)
    counts: dict[datetime, dict[str, int]] = defaultdict(lambda: {s: 0 for s in SEVERITIES})
    for a, t in zip(alerts, times):
        counts[floor(t)][a["severity"]] += 1
    start, end = min(counts), max(counts)
    points, cur = [], start
    while cur <= end and len(points) < 240:
        points.append({"t": cur.isoformat(timespec="minutes"), **counts.get(cur, {s: 0 for s in SEVERITIES})})
        cur += step
    return {"bucket": name, "points": points}
