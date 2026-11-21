"""Membuat log sintetis untuk pengujian (hanya data buatan, tanpa target nyata).

Penyerang A (203.0.113.45) muncul di SSH, web, dan Suricata sehingga bisa dikorelasikan.
Penyerang B (198.51.100.77) hanya sekali mencoba XSS (prioritas rendah).
Jalankan:  python tools/generate_logs.py
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "sample_logs"
BASE = datetime(2026, 11, 21, 10, 0, 0)
ATTACKER_A = "203.0.113.45"
ATTACKER_B = "198.51.100.77"
SCANNER_TARGET = "10.0.0.5"
rng = random.Random(42)


def sys_line(ts: datetime, pid: int, msg: str, proc: str = "sshd") -> str:
    return f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} web01 {proc}[{pid}]: {msg}"


def web_line(ip: str, ts: datetime, req: str, status: int, size: int, ua: str) -> str:
    return f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0700] "{req}" {status} {size} "-" "{ua}"'


BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/118.0 Safari/537.36"
SQLMAP = "sqlmap/1.7.2#stable (https://sqlmap.org)"


def normal_auth() -> list[str]:
    lines = []
    for i in range(12):
        ts = BASE + timedelta(minutes=5 * i, seconds=rng.randint(0, 50))
        user, ip = rng.choice([("budi", "192.168.1.10"), ("sari", "192.168.1.11"), ("admin", "192.168.1.12")])
        lines.append(sys_line(ts, 1200 + i, f"Accepted publickey for {user} from {ip} port {rng.randint(40000, 60000)} ssh2"))
        lines.append(sys_line(ts, 1200 + i, f"pam_unix(sshd:session): session opened for user {user}", "sshd"))
    # salah ketik password 2x oleh pengguna sah (harus TIDAK memicu alert)
    t = BASE + timedelta(minutes=33)
    for k in range(2):
        lines.append(sys_line(t + timedelta(seconds=8 * k), 1300, "Failed password for sari from 192.168.1.11 port 50111 ssh2"))
    lines.append(sys_line(t + timedelta(seconds=25), 1300, "Accepted password for sari from 192.168.1.11 port 50111 ssh2"))
    lines.append(sys_line(BASE + timedelta(minutes=40), 900, "(root) CMD (run-parts /etc/cron.hourly)", "CRON"))
    return lines


def auth_bruteforce() -> list[str]:
    lines = normal_auth()
    t = BASE + timedelta(minutes=20)
    users = ["root", "admin", "ubuntu", "test", "oracle", "postgres"]
    for i in range(50):
        u = users[i % len(users)]
        inv = "invalid user " if u in ("oracle", "postgres", "test") else ""
        lines.append(sys_line(t + timedelta(seconds=3 * i), 2100 + i, f"Failed password for {inv}{u} from {ATTACKER_A} port {40000 + i} ssh2"))
    lines.append(sys_line(t + timedelta(seconds=160), 2200, f"Accepted password for root from {ATTACKER_A} port 40122 ssh2"))
    lines.append(sys_line(t + timedelta(seconds=161), 2200, "pam_unix(sshd:session): session opened for user root", "sshd"))
    return sorted(lines, key=lambda l: (l[:15]))


PAGES = ["/", "/products?id=3", "/products?id=7", "/login", "/static/app.css", "/about", "/contact", "/cart"]
LEGIT_TRICKY = [  # tampak mirip serangan tetapi sah (uji false positive)
    "GET /blog/my--post HTTP/1.1",
    "GET /products?category=union&select=blue HTTP/1.1",
    "GET /search?q=rock+and+roll HTTP/1.1",
    "GET /search?q=salt+%26+pepper HTTP/1.1",
]


def normal_web(n: int = 60) -> list[str]:
    lines = []
    ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12", "36.68.14.21", "114.125.9.77", "182.1.55.3"]
    for i in range(n):
        ts = BASE + timedelta(seconds=40 * i + rng.randint(0, 20))
        req = f"GET {rng.choice(PAGES)} HTTP/1.1"
        lines.append(web_line(rng.choice(ips), ts, req, 200, rng.randint(500, 9000), BROWSER))
    for j, req in enumerate(LEGIT_TRICKY):
        lines.append(web_line("36.68.14.21", BASE + timedelta(minutes=30, seconds=10 * j), req, 200, 1234, BROWSER))
    return sorted(lines, key=lambda l: l.split("[")[1])


def web_attacks() -> list[str]:
    lines = normal_web(40)
    t = BASE + timedelta(minutes=18)
    payloads = [
        "/products?id=1%27%20OR%20%271%27%3D%271",
        "/products?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
        "/search?q=1;DROP%20TABLE%20users",
        "/products?id=1%20AND%20sleep(5)",
        "/products?id=1%20OR%201=1",
        "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
        "/comment?x=%22%20onerror%3Dalert(1)",
        "/download?file=../../../../etc/passwd",
        "/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/admin/.git/config",
    ]
    for i, p in enumerate(payloads * 2):
        lines.append(web_line(ATTACKER_A, t + timedelta(seconds=4 * i), f"GET {p} HTTP/1.1",
                              200 if i % 5 == 4 else 403, rng.randint(200, 5000), SQLMAP))
    lines.append(web_line(ATTACKER_B, BASE + timedelta(minutes=35), "GET /search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E HTTP/1.1", 200, 800, BROWSER))
    return sorted(lines, key=lambda l: l.split("[")[1])


def suricata_scan() -> list[str]:
    recs = []
    t = BASE + timedelta(minutes=15)
    for i, port in enumerate([21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433, 3306, 3389, 5432, 5900, 8080, 8443, 9200, 27017]):
        ts = t + timedelta(milliseconds=500 * i)
        recs.append({"timestamp": f"{ts:%Y-%m-%dT%H:%M:%S}.{ts.microsecond:06d}+0700", "event_type": "flow",
                     "src_ip": ATTACKER_A, "src_port": 50000 + i, "dest_ip": SCANNER_TARGET, "dest_port": port, "proto": "TCP"})
    ts = t + timedelta(seconds=12)
    recs.append({"timestamp": f"{ts:%Y-%m-%dT%H:%M:%S}.000000+0700", "event_type": "alert", "src_ip": ATTACKER_A,
                 "dest_ip": SCANNER_TARGET, "dest_port": 22,
                 "alert": {"signature": "ET SCAN Potential SSH Scan", "category": "Attempted Information Leak", "severity": 2}})
    ts = BASE + timedelta(minutes=50)
    recs.append({"timestamp": f"{ts:%Y-%m-%dT%H:%M:%S}.000000+0700", "event_type": "alert", "src_ip": "192.168.1.50",
                 "dest_ip": "8.8.8.8", "dest_port": 53,
                 "alert": {"signature": "ET POLICY External DNS Resolver Use", "category": "Potential Corporate Privacy Violation", "severity": 3}})
    for i in range(6):  # trafik normal
        ts = BASE + timedelta(minutes=10 + i)
        recs.append({"timestamp": f"{ts:%Y-%m-%dT%H:%M:%S}.000000+0700", "event_type": "flow", "src_ip": "192.168.1.10",
                     "dest_ip": SCANNER_TARGET, "dest_port": 443, "proto": "TCP"})
    recs.sort(key=lambda r: r["timestamp"])
    return [json.dumps(r) for r in recs]


def corrupted() -> list[str]:
    lines = normal_web(15)
    lines[3:3] = ["@@@@ ini bukan log yang valid @@@@", "\x00\x01\x02 binary garbage", "192.168.1.10 - - [bukan-tanggal] \"GET / HTTP/1.1\" 200 12"]
    lines.append('203.0.113.9 - - [21/Nov/2026:10:44:00 +0700] "GET /products?id=1%20OR%201=1 HTTP/1.1" 200 500 "-" "curl/8.0"')
    lines.append("baris terpotong 203.0.113.9 - - [21/Nov/2026:10")
    return lines


def write(name: str, lines: list[str]) -> None:
    (OUT / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"ditulis {name}: {len(lines)} baris")


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    write("auth_bruteforce.log", auth_bruteforce())
    write("normal_auth.log", normal_auth())
    write("web_attacks.log", web_attacks())
    write("normal_web.log", normal_web())
    write("suricata_scan.json", suricata_scan())
    write("corrupted.log", corrupted())
