"""Model data: Event (hasil normalisasi log) dan Alert (hasil deteksi)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

SEVERITIES = ["Critical", "High", "Medium", "Low"]
SEVERITY_ORDER = {s: i for i, s in enumerate(SEVERITIES)}  # 0 = paling tinggi
SEVERITY_WEIGHT = {"Critical": 8, "High": 5, "Medium": 3, "Low": 1}
STATUSES = ["New", "Investigating", "True Positive", "False Positive"]


@dataclass
class Event:
    """Format standar untuk semua sumber log."""
    ts: datetime
    src_ip: str
    source: str            # ssh | web | suricata | wazuh
    event_type: str        # ssh_fail | ssh_success | http_request | ids_alert | flow | wazuh_alert
    raw: str
    dest_ip: str | None = None
    dest_port: int | None = None
    user: str | None = None
    request: str | None = None
    user_agent: str | None = None
    status: int | None = None
    signature: str | None = None
    sensor_severity: str | None = None   # sudah dipetakan ke Critical/High/Medium/Low
    mitre: list[str] = field(default_factory=list)


@dataclass
class Alert:
    rule_id: str
    rule_name: str
    severity: str
    src_ip: str
    first_seen: datetime
    last_seen: datetime
    count: int
    mitre: list[str]
    recommendation: str
    detail: str
    evidence: list[str]
    source: str
    score: int = 0
    correlated: bool = False

    def to_row(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "src_ip": self.src_ip,
            "first_seen": self.first_seen.isoformat(timespec="seconds"),
            "last_seen": self.last_seen.isoformat(timespec="seconds"),
            "count": self.count,
            "score": self.score,
            "correlated": int(self.correlated),
            "mitre": self.mitre,
            "recommendation": self.recommendation,
            "detail": self.detail,
            "evidence": self.evidence,
        }
