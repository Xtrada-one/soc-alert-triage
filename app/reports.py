"""Pembuatan laporan insiden (Markdown)."""
from __future__ import annotations

from collections import Counter
from datetime import datetime

from .models import SEVERITIES


def markdown_report(upload: dict, incidents: list[dict], alerts: list[dict]) -> str:
    sev = Counter(a["severity"] for a in alerts)
    out = [
        "# Laporan Insiden Keamanan",
        "",
        f"- Sumber log: {upload['filename']} (format: {upload['format']})",
        f"- Dianalisis: {upload['uploaded_at']}  |  Laporan dibuat: {datetime.now():%Y-%m-%d %H:%M}",
        f"- Baris log: {upload['total_lines']}  |  Event terbaca: {upload['events']}  |  Baris tidak valid: {upload['invalid_lines']}",
        f"- Total alert: {len(alerts)}  |  Total insiden (per IP): {len(incidents)}",
        "",
        "## Ringkasan severity",
        "",
        "| Severity | Jumlah alert |",
        "| --- | --- |",
        *[f"| {s} | {sev.get(s, 0)} |" for s in SEVERITIES],
        "",
        "## Insiden (diurutkan dari prioritas tertinggi)",
    ]
    if not incidents:
        out += ["", "Tidak ada alert pada log ini."]
    for n, inc in enumerate(incidents, 1):
        out += [
            "",
            f"### {n}. {inc['src_ip']} - {inc['severity']} (skor {inc['score']})",
            "",
            f"- Periode: {inc['first_seen']} sampai {inc['last_seen']}",
            f"- Status: {inc['status']}" + ("  |  Terkorelasi lintas rule" if inc["correlated"] else ""),
            f"- Teknik MITRE ATT&CK: {', '.join(inc['mitre']) or '-'}",
            "",
            "**Rule yang terpicu**",
            "",
        ]
        for a in inc["alerts"]:
            out.append(f"- {a['rule_id']} {a['rule_name']} ({a['severity']}, {a['count']} kejadian): {a['detail']}")
        out += ["", "**Rekomendasi respons**", ""]
        out += [f"{i}. {r}" for i, r in enumerate(inc["recommendations"], 1)]
        top = inc["alerts"][0]
        if top["evidence"]:
            out += ["", f"**Contoh bukti ({top['rule_id']})**", "", "```"]
            out += top["evidence"][:3]
            out += ["```"]
    out += ["", "---", "Dibuat oleh SOC Alert Triage Dashboard. Hasil deteksi berbasis aturan perlu diverifikasi analis."]
    return "\n".join(out) + "\n"
