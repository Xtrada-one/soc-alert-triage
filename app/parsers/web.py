"""Parser access log Nginx/Apache (combined log format)."""
from __future__ import annotations

import re
from datetime import datetime

from ..models import Event

_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<req>[^"]*)" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<ref>[^"]*)" "(?P<ua>[^"]*)")?'
)


def matches(line: str) -> bool:
    return bool(_COMBINED.match(line))


def parse(lines: list[str]) -> tuple[list[Event], int]:
    events: list[Event] = []
    invalid = 0
    for line in lines:
        s = line.strip()
        if not s:
            continue
        m = _COMBINED.match(s)
        if not m:
            invalid += 1
            continue
        try:
            ts = datetime.strptime(m["ts"].split()[0], "%d/%b/%Y:%H:%M:%S")
        except ValueError:
            invalid += 1
            continue
        events.append(Event(
            ts=ts, src_ip=m["ip"], source="web", event_type="http_request", raw=s,
            request=m["req"], user_agent=m["ua"], status=int(m["status"]),
        ))
    return events, invalid
