from __future__ import annotations

from ..models import SEVERITY_WEIGHT, Alert


def compute_score(alert: Alert) -> int:
    """skor = bobot severity + bonus jumlah kejadian (maks 3) + bonus korelasi (2)."""
    volume_bonus = min(3, alert.count // 10)
    correlation_bonus = 2 if alert.correlated else 0
    return SEVERITY_WEIGHT[alert.severity] + volume_bonus + correlation_bonus
