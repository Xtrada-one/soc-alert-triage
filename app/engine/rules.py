"""Rule engine: membaca rules.yaml, menjalankan deteksi, korelasi, dan skor."""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from urllib.parse import unquote_plus

import yaml

from ..models import SEVERITY_ORDER, SEVERITY_WEIGHT, Alert, Event
from .scoring import compute_score

MAX_FIELD_LEN = 2000   # batasi panjang input yang dicocokkan (cegah regex lambat)
EVIDENCE_MAX = 5
RAW_MAX = 300


def load_rules(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        rules = yaml.safe_load(f)["rules"]
    for r in rules:
        if r["severity"] not in SEVERITY_WEIGHT:
            raise ValueError(f"Severity tidak valid di rule {r['id']}: {r['severity']}")
        if r["type"] == "pattern":
            r["_compiled"] = [re.compile(p, re.IGNORECASE) for p in r["patterns"]]
    return rules


def _decode(s: str) -> str:
    for _ in range(2):  # decode dua kali agar %252e%252e ikut terbaca
        s = unquote_plus(s)
    return s


def _evidence(raws: list[str]) -> list[str]:
    raws = [r[:RAW_MAX] for r in raws]
    return raws if len(raws) <= EVIDENCE_MAX else raws[:3] + raws[-2:]


def _make_alert(rule: dict, ip: str, evs: list[Event], detail: str, count: int | None = None) -> Alert:
    return Alert(
        rule_id=rule["id"], rule_name=rule["name"], severity=rule["severity"], src_ip=ip,
        first_seen=evs[0].ts, last_seen=evs[-1].ts, count=count or len(evs),
        mitre=list(rule.get("mitre", [])), recommendation=rule.get("recommendation", ""),
        detail=detail, evidence=_evidence([e.raw for e in evs]), source=evs[0].source,
    )


def _densest_window(times, seconds):
    """Indeks (kiri, kanan) jendela waktu dengan kejadian terbanyak; `times` harus terurut."""
    left, best, best_len = 0, (0, 0), 0
    for right, t in enumerate(times):
        while (t - times[left]).total_seconds() > seconds:
            left += 1
        if right - left + 1 > best_len:
            best, best_len = (left, right), right - left + 1
    return best


def _threshold(rule, by_ip):
    et, need, win = rule["match"]["event_type"], rule["threshold"], rule["window_seconds"]
    for ip, evs in by_ip.items():
        sel = [e for e in evs if e.event_type == et]
        if len(sel) < need:
            continue
        i, j = _densest_window([e.ts for e in sel], win)
        grp = sel[i:j + 1]
        if len(grp) >= need:
            yield _make_alert(rule, ip, grp, rule["detail"].format(n=len(grp), window=win))


def _sequence(rule, by_ip):
    fail_t, ok_t = rule["fail_event"], rule["success_event"]
    need, win = rule["fail_threshold"], rule["window_seconds"]
    for ip, evs in by_ip.items():
        recent: list[Event] = []
        for e in evs:
            if e.event_type == fail_t:
                recent.append(e)
            elif e.event_type == ok_t:
                recent = [x for x in recent if (e.ts - x.ts).total_seconds() <= win]
                if len(recent) >= need:
                    detail = rule["detail"].format(n=len(recent), user=e.user)
                    yield _make_alert(rule, ip, recent + [e], detail)
                    break
                continue
            # buang kegagalan yang sudah di luar jendela agar list tetap kecil
            while recent and (e.ts - recent[0].ts).total_seconds() > win:
                recent.pop(0)


def _pattern(rule, by_ip):
    fld, et = rule["field"], rule.get("event_type")
    decode = rule.get("decode", True)
    for ip, evs in by_ip.items():
        hits = []
        for e in evs:
            if et and e.event_type != et:
                continue
            val = getattr(e, fld)
            if not val:
                continue
            val = val[:MAX_FIELD_LEN]
            text = _decode(val) if decode else val
            if any(p.search(text) for p in rule["_compiled"]):
                hits.append(e)
        if len(hits) >= rule.get("min_hits", 1):
            yield _make_alert(rule, ip, hits, rule["detail"].format(n=len(hits)))


def _distinct_ports(rule, by_ip):
    types, need, win = set(rule["match"]["event_types"]), rule["threshold"], rule["window_seconds"]
    for ip, evs in by_ip.items():
        sel = [e for e in evs if e.event_type in types and e.dest_port is not None]
        if len(sel) < need:
            continue
        counts: Counter = Counter()
        left, best = 0, None
        for right, e in enumerate(sel):
            counts[e.dest_port] += 1
            while (e.ts - sel[left].ts).total_seconds() > win:
                p = sel[left].dest_port
                counts[p] -= 1
                if counts[p] == 0:
                    del counts[p]
                left += 1
            if len(counts) >= need and (best is None or len(counts) > best[0]):
                best = (len(counts), left, right)
        if best:
            n, l, r = best
            yield _make_alert(rule, ip, sel[l:r + 1], rule["detail"].format(n=n, window=win))


def _native(rule, events):
    groups: dict[tuple, list[Event]] = defaultdict(list)
    for e in events:
        if e.event_type in ("ids_alert", "wazuh_alert") and e.sensor_severity:
            groups[(e.src_ip, e.signature or "alert")].append(e)
    for (ip, sig), evs in groups.items():
        best = min((e.sensor_severity for e in evs), key=SEVERITY_ORDER.get)
        a = _make_alert(rule, ip, evs, f"Alert dari {evs[0].source}: {sig}")
        a.rule_name = f"Alert sensor: {sig}"
        a.severity = best
        a.mitre = sorted({m for e in evs for m in e.mitre})
        yield a


_DETECTORS = {
    "threshold": _threshold, "sequence": _sequence, "pattern": _pattern,
    "distinct_ports": _distinct_ports,
}


def analyze(events: list[Event], rules: list[dict], whitelist=()) -> list[Alert]:
    wl = set(whitelist)
    events = sorted((e for e in events if e.src_ip not in wl), key=lambda e: e.ts)
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for e in events:
        by_ip[e.src_ip].append(e)

    alerts: list[Alert] = []
    corr_rule = None
    for rule in rules:
        t = rule["type"]
        if t == "correlation":
            corr_rule = rule
        elif t == "native":
            alerts.extend(_native(rule, events))
        else:
            alerts.extend(_DETECTORS[t](rule, by_ip))

    # Korelasi: IP yang memicu >= 2 rule berbeda dianggap terkorelasi (bonus skor);
    # IP yang memicu >= min_rules rule berbeda menghasilkan alert R08.
    per_ip: dict[str, list[Alert]] = defaultdict(list)
    for a in alerts:
        per_ip[a.src_ip].append(a)
    for ip, als in per_ip.items():
        if len({a.rule_id for a in als}) >= 2:
            for a in als:
                a.correlated = True
    if corr_rule:
        for ip, als in per_ip.items():
            ids = sorted({a.rule_id for a in als})
            if len(ids) >= corr_rule["min_rules"]:
                alerts.append(Alert(
                    rule_id=corr_rule["id"], rule_name=corr_rule["name"], severity=corr_rule["severity"],
                    src_ip=ip, first_seen=min(a.first_seen for a in als),
                    last_seen=max(a.last_seen for a in als), count=len(ids),
                    mitre=sorted({m for a in als for m in a.mitre}),
                    recommendation=corr_rule["recommendation"],
                    detail=f"{len(ids)} rule berbeda terpicu dari IP yang sama: {', '.join(ids)}",
                    evidence=[f"{a.rule_id} {a.rule_name}: {a.detail}" for a in als][:EVIDENCE_MAX],
                    source="korelasi", correlated=True,
                ))

    for a in alerts:
        a.score = compute_score(a)
    alerts.sort(key=lambda a: (-a.score, SEVERITY_ORDER[a.severity], a.first_seen))
    return alerts
