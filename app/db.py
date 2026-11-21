"""Lapisan SQLite. Semua query memakai parameter (bukan string concatenation)."""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS uploads (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    format TEXT NOT NULL,
    uploaded_at TEXT NOT NULL,
    total_lines INTEGER NOT NULL,
    events INTEGER NOT NULL,
    invalid_lines INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    upload_id INTEGER NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    severity TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    count INTEGER NOT NULL,
    score INTEGER NOT NULL,
    correlated INTEGER NOT NULL,
    mitre TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    detail TEXT NOT NULL,
    evidence TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'New'
);
CREATE INDEX IF NOT EXISTS idx_alerts_upload ON alerts(upload_id);
CREATE TABLE IF NOT EXISTS whitelist (
    ip TEXT PRIMARY KEY,
    note TEXT NOT NULL DEFAULT '',
    added_at TEXT NOT NULL
);
"""


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DB_PATH"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_app(app):
    path = app.config["DB_PATH"]
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()
    app.teardown_appcontext(close_db)


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _alert_dict(row: sqlite3.Row) -> dict:
    d = dict(row)
    d["mitre"] = json.loads(d["mitre"])
    d["evidence"] = json.loads(d["evidence"])
    d["correlated"] = bool(d["correlated"])
    return d


# ---- uploads & alerts -------------------------------------------------------
def save_analysis(filename, fmt, total_lines, events, invalid, alerts) -> int:
    db = get_db()
    cur = db.execute(
        "INSERT INTO uploads (filename, format, uploaded_at, total_lines, events, invalid_lines) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (filename, fmt, _now(), total_lines, events, invalid),
    )
    upload_id = cur.lastrowid
    for a in alerts:
        r = a.to_row()
        db.execute(
            "INSERT INTO alerts (upload_id, rule_id, rule_name, severity, src_ip, first_seen, last_seen, "
            "count, score, correlated, mitre, recommendation, detail, evidence) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (upload_id, r["rule_id"], r["rule_name"], r["severity"], r["src_ip"], r["first_seen"],
             r["last_seen"], r["count"], r["score"], r["correlated"], json.dumps(r["mitre"]),
             r["recommendation"], r["detail"], json.dumps(r["evidence"])),
        )
    db.commit()
    return upload_id


def list_uploads() -> list[dict]:
    rows = get_db().execute("SELECT * FROM uploads ORDER BY id DESC").fetchall()
    return [dict(r) for r in rows]


def get_upload(upload_id: int) -> dict | None:
    row = get_db().execute("SELECT * FROM uploads WHERE id = ?", (upload_id,)).fetchone()
    return dict(row) if row else None


def latest_upload_id() -> int | None:
    row = get_db().execute("SELECT MAX(id) AS id FROM uploads").fetchone()
    return row["id"]


def delete_upload(upload_id: int) -> bool:
    db = get_db()
    cur = db.execute("DELETE FROM uploads WHERE id = ?", (upload_id,))
    db.commit()
    return cur.rowcount > 0


def get_alerts(upload_id: int, severity=None, ip=None, status=None, q=None) -> list[dict]:
    sql = "SELECT * FROM alerts WHERE upload_id = ?"
    params: list = [upload_id]
    if severity:
        sql += " AND severity = ?"
        params.append(severity)
    if ip:
        sql += " AND src_ip = ?"
        params.append(ip)
    if status:
        sql += " AND status = ?"
        params.append(status)
    if q:
        sql += " AND (rule_name LIKE ? OR detail LIKE ? OR src_ip LIKE ? OR rule_id LIKE ?)"
        params.extend([f"%{q}%"] * 4)
    sql += " ORDER BY score DESC, id"
    return [_alert_dict(r) for r in get_db().execute(sql, params).fetchall()]


def update_status(alert_id: int, status: str) -> bool:
    db = get_db()
    cur = db.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
    db.commit()
    return cur.rowcount > 0


# ---- whitelist --------------------------------------------------------------
def whitelist_all() -> list[dict]:
    return [dict(r) for r in get_db().execute("SELECT * FROM whitelist ORDER BY added_at DESC").fetchall()]


def whitelist_ips() -> set[str]:
    return {r["ip"] for r in get_db().execute("SELECT ip FROM whitelist").fetchall()}


def whitelist_add(ip: str, note: str) -> None:
    db = get_db()
    db.execute("INSERT OR REPLACE INTO whitelist (ip, note, added_at) VALUES (?, ?, ?)", (ip, note, _now()))
    db.commit()


def whitelist_remove(ip: str) -> bool:
    db = get_db()
    cur = db.execute("DELETE FROM whitelist WHERE ip = ?", (ip,))
    db.commit()
    return cur.rowcount > 0
