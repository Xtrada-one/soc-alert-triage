"""Endpoint API dan halaman."""
from __future__ import annotations

import ipaddress
import os
from collections import Counter
from datetime import datetime

from flask import Blueprint, Response, current_app, jsonify, render_template, request, send_from_directory

from . import db, llm
from .engine.incidents import build_incidents, build_timeline
from .engine.rules import analyze
from .models import SEVERITIES, STATUSES
from .parsers import parse_text
from .reports import markdown_report

bp = Blueprint("main", __name__)

SCENARIOS = {
    "1": ("Skenario 1: SSH brute force", ["auth_bruteforce.log"]),
    "2": ("Skenario 2: Serangan web (SQLi, XSS, traversal)", ["web_attacks.log"]),
    "3": ("Skenario 3: Trafik normal (uji false positive)", ["normal_auth.log", "normal_web.log"]),
    "4": ("Skenario 4: Serangan multi-sumber (korelasi)", ["auth_bruteforce.log", "web_attacks.log", "suricata_scan.json"]),
    "5": ("Skenario 5: Log rusak", ["corrupted.log"]),
}


def _err(msg: str, code: int = 400):
    return jsonify({"error": msg}), code


def _upload_id() -> int | None:
    raw = request.args.get("upload_id")
    if raw is None or raw == "":
        return db.latest_upload_id()
    try:
        return int(raw)
    except ValueError:
        return None


def _run_analysis(named_texts: list[tuple[str, str]], fmt: str):
    year = current_app.config["LOG_YEAR"] or datetime.now().year
    events, formats, total, invalid = [], [], 0, 0
    for name, text in named_texts:
        try:
            res = parse_text(text, fmt if len(named_texts) == 1 else "auto", year)
        except ValueError as e:
            raise ValueError(f"{name}: {e}") from e
        events.extend(res.events)
        formats.append(res.fmt)
        total += res.total_lines
        invalid += res.invalid
    wl = db.whitelist_ips()
    alerts = analyze(events, current_app.config["RULES"], wl)
    whitelisted = sum(1 for e in events if e.src_ip in wl)
    names = ", ".join(n for n, _ in named_texts)[:200]
    upload_id = db.save_analysis(names, ", ".join(sorted(set(formats))), total, len(events), invalid, alerts)
    return {
        "upload_id": upload_id, "formats": sorted(set(formats)), "total_lines": total,
        "events": len(events), "invalid_lines": invalid, "alerts": len(alerts),
        "incidents": len({a.src_ip for a in alerts}), "whitelisted_events": whitelisted,
    }


# ---- halaman -----------------------------------------------------------------
@bp.get("/")
def index():
    return send_from_directory(current_app.static_folder, "index.html")


@bp.get("/report")
def report_page():
    uid = _upload_id()
    upload = db.get_upload(uid) if uid else None
    if not upload:
        return "Belum ada hasil analisis.", 404
    alerts = db.get_alerts(uid)
    return render_template("report.html", upload=upload, incidents=build_incidents(alerts), alerts=alerts,
                           severities=SEVERITIES, sev=Counter(a["severity"] for a in alerts),
                           now=datetime.now().strftime("%Y-%m-%d %H:%M"))


# ---- API ---------------------------------------------------------------------
@bp.get("/api/health")
def health():
    return jsonify({"status": "ok"})


@bp.get("/api/config")
def config():
    return jsonify({
        "llm_enabled": current_app.config["LLM_ENABLED"],
        "scenarios": [{"key": k, "label": v[0]} for k, v in SCENARIOS.items()],
        "statuses": STATUSES, "severities": SEVERITIES,
    })


@bp.post("/api/upload")
def upload():
    files = [f for f in request.files.getlist("file") if f and f.filename]
    if not files:
        return _err("Pilih minimal satu file log.")
    named = [(os.path.basename(f.filename), f.read().decode("utf-8", errors="replace")) for f in files]
    try:
        return jsonify(_run_analysis(named, request.form.get("format", "auto"))), 201
    except ValueError as e:
        return _err(str(e))


@bp.post("/api/analyze-scenario")
def analyze_scenario():
    key = str((request.get_json(silent=True) or {}).get("key", ""))
    if key not in SCENARIOS:
        return _err("Skenario tidak dikenal.")
    base = current_app.config["SAMPLES_DIR"]
    named = []
    for fname in SCENARIOS[key][1]:
        path = os.path.join(base, fname)
        if not os.path.isfile(path):
            return _err(f"File contoh tidak ditemukan: {fname}. Jalankan tools/generate_logs.py.", 404)
        with open(path, encoding="utf-8", errors="replace") as f:
            named.append((fname, f.read()))
    try:
        return jsonify(_run_analysis(named, "auto")), 201
    except ValueError as e:
        return _err(str(e))


@bp.get("/api/uploads")
def uploads():
    return jsonify(db.list_uploads())


@bp.delete("/api/uploads/<int:upload_id>")
def delete_upload(upload_id: int):
    return jsonify({"deleted": True}) if db.delete_upload(upload_id) else _err("Tidak ditemukan.", 404)


@bp.get("/api/summary")
def summary():
    uid = _upload_id()
    upload = db.get_upload(uid) if uid else None
    if not upload:
        return jsonify({"upload": None})
    alerts = db.get_alerts(uid)
    incidents = build_incidents(alerts)
    sev = Counter(a["severity"] for a in alerts)
    return jsonify({
        "upload": upload,
        "severity_counts": {s: sev.get(s, 0) for s in SEVERITIES},
        "total_alerts": len(alerts),
        "total_incidents": len(incidents),
        "top_ips": [{"src_ip": i["src_ip"], "score": i["score"], "severity": i["severity"],
                     "alert_count": i["alert_count"]} for i in incidents[:8]],
        "timeline": build_timeline(alerts),
    })


@bp.get("/api/incidents")
def incidents():
    uid = _upload_id()
    if not uid:
        return jsonify([])
    return jsonify(build_incidents(db.get_alerts(uid)))


@bp.get("/api/alerts")
def alerts():
    sev, status = request.args.get("severity") or None, request.args.get("status") or None
    if sev and sev not in SEVERITIES:
        return _err("Severity tidak valid.")
    if status and status not in STATUSES:
        return _err("Status tidak valid.")
    uid = _upload_id()
    if not uid:
        return jsonify([])
    return jsonify(db.get_alerts(uid, sev, request.args.get("ip") or None, status, request.args.get("q") or None))


@bp.patch("/api/alerts/<int:alert_id>")
def set_status(alert_id: int):
    status = (request.get_json(silent=True) or {}).get("status")
    if status not in STATUSES:
        return _err("Status tidak valid.")
    return jsonify({"updated": True}) if db.update_status(alert_id, status) else _err("Alert tidak ditemukan.", 404)


@bp.get("/api/whitelist")
def whitelist_list():
    return jsonify(db.whitelist_all())


@bp.post("/api/whitelist")
def whitelist_add():
    body = request.get_json(silent=True) or {}
    try:
        ip = str(ipaddress.ip_address(str(body.get("ip", "")).strip()))
    except ValueError:
        return _err("Alamat IP tidak valid.")
    db.whitelist_add(ip, str(body.get("note", ""))[:200])
    return jsonify({"added": ip}), 201


@bp.delete("/api/whitelist/<path:ip>")
def whitelist_delete(ip: str):
    return jsonify({"deleted": True}) if db.whitelist_remove(ip) else _err("IP tidak ada di whitelist.", 404)


@bp.get("/api/report.md")
def report_md():
    uid = _upload_id()
    upload = db.get_upload(uid) if uid else None
    if not upload:
        return _err("Belum ada hasil analisis.", 404)
    alerts = db.get_alerts(uid)
    text = markdown_report(upload, build_incidents(alerts), alerts)
    return Response(text, mimetype="text/markdown", headers={
        "Content-Disposition": f"attachment; filename=laporan-insiden-{uid}.md"})


@bp.post("/api/explain")
def explain():
    if not current_app.config["LLM_ENABLED"]:
        return jsonify({"enabled": False, "text": None})
    ip = str((request.get_json(silent=True) or {}).get("ip", ""))
    uid = _upload_id()
    inc = next((i for i in build_incidents(db.get_alerts(uid)) if i["src_ip"] == ip), None) if uid else None
    if not inc:
        return _err("Insiden tidak ditemukan.", 404)
    try:
        text = llm.explain(inc, current_app.config["OLLAMA_URL"], current_app.config["OLLAMA_MODEL"])
    except Exception as e:  # jaringan/model bermasalah: aplikasi tetap jalan tanpa LLM
        return _err(f"LLM tidak dapat dihubungi: {type(e).__name__}", 502)
    return jsonify({"enabled": True, "text": text})
