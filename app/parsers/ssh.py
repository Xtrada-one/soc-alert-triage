"""Parser auth.log / journal sshd (format syslog klasik maupun ISO)."""
from __future__ import annotations

import re
from datetime import datetime

from ..models import Event
from .common import parse_iso

_SYSLOG = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s\[:]+)(?:\[\d+\])?:\s*(?P<msg>.*)$"
)
_ISO = re.compile(
    r"^(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\S*\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s\[:]+)(?:\[\d+\])?:\s*(?P<msg>.*)$"
)
_FAIL = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)
_OK = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive/pam) for "
    r"(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+) port (?P<port>\d+)"
)


def matches(line: str) -> bool:
    return bool(_ISO.match(line) or _SYSLOG.match(line))


def parse(lines: list[str], year: int) -> tuple[list[Event], int]:
    events: list[Event] = []
    invalid = 0
    for line in lines:
        s = line.strip()
        if not s:
            continue
        try:
            m = _ISO.match(s)
            if m:
                ts = parse_iso(m["iso"])
            else:
                m = _SYSLOG.match(s)
                if not m:
                    invalid += 1
                    continue
                ts = datetime.strptime(
                    f"{year} {m['mon']} {int(m['day'])} {m['time']}", "%Y %b %d %H:%M:%S"
                )
        except ValueError:
            invalid += 1
            continue
        if not m["proc"].startswith("sshd"):
            continue  # baris sah tapi bukan dari sshd
        msg = m["msg"]
        f = _FAIL.search(msg)
        if f:
            events.append(Event(ts=ts, src_ip=f["ip"], source="ssh", event_type="ssh_fail",
                                raw=s, user=f["user"], dest_port=22))
            continue
        ok = _OK.search(msg)
        if ok:
            events.append(Event(ts=ts, src_ip=ok["ip"], source="ssh", event_type="ssh_success",
                                raw=s, user=ok["user"], dest_port=22))
    return events, invalid
