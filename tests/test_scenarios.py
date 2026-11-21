"""Skenario pengujian SOC Alert Triage Dashboard.

Jalankan:  python -m unittest discover -s tests -v   (atau: pytest)
"""
import io
import os
import tempfile
import unittest

from app import create_app
from app.engine.rules import analyze, load_rules
from app.parsers import detect_format, parse_text

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ATTACKER_A = "203.0.113.45"
ATTACKER_B = "198.51.100.77"
RULES = load_rules(os.path.join(ROOT, "app", "rules", "rules.yaml"))


def sample(name: str) -> str:
    with open(os.path.join(ROOT, "sample_logs", name), encoding="utf-8") as f:
        return f.read()


def alerts_for(*names, whitelist=()):
    events = []
    for n in names:
        events += parse_text(sample(n), "auto", 2026).events
    return analyze(events, RULES, whitelist)


def rule_ids(alerts, ip):
    return {a.rule_id for a in alerts if a.src_ip == ip}


class EngineScenarios(unittest.TestCase):
    def test_1_ssh_bruteforce_success_is_critical(self):
        alerts = alerts_for("auth_bruteforce.log")
        self.assertTrue({"R01", "R02"} <= rule_ids(alerts, ATTACKER_A))
        r02 = next(a for a in alerts if a.rule_id == "R02")
        self.assertEqual(r02.severity, "Critical")
        self.assertIn("T1078", r02.mitre)
        self.assertEqual(alerts[0].src_ip, ATTACKER_A)  # prioritas teratas

    def test_2_web_attacks_detected(self):
        alerts = alerts_for("web_attacks.log")
        self.assertTrue({"R03", "R04", "R05", "R07"} <= rule_ids(alerts, ATTACKER_A))
        self.assertEqual(rule_ids(alerts, ATTACKER_B), {"R04"})  # penyerang B: hanya XSS

    def test_3_normal_traffic_no_alerts(self):
        self.assertEqual(alerts_for("normal_auth.log", "normal_web.log"), [])

    def test_4_cross_source_correlation(self):
        alerts = alerts_for("auth_bruteforce.log", "web_attacks.log", "suricata_scan.json")
        self.assertIn("R08", rule_ids(alerts, ATTACKER_A))
        self.assertIn("R06", rule_ids(alerts, ATTACKER_A))  # port scan dari Suricata
        r08 = next(a for a in alerts if a.rule_id == "R08")
        self.assertEqual(r08.severity, "Critical")
        self.assertTrue(all(a.correlated for a in alerts if a.src_ip == ATTACKER_A))

    def test_5_corrupted_log_does_not_crash(self):
        res = parse_text(sample("corrupted.log"), "auto", 2026)
        self.assertGreaterEqual(res.invalid, 3)
        self.assertTrue(res.events)
        alerts = analyze(res.events, RULES)
        self.assertIn("R03", {a.rule_id for a in alerts})  # baris valid tetap dianalisis


class ParserAndRuleEdgeCases(unittest.TestCase):
    def test_format_detection(self):
        self.assertEqual(detect_format(sample("auth_bruteforce.log")), "ssh")
        self.assertEqual(detect_format(sample("web_attacks.log")), "web")
        self.assertEqual(detect_format(sample("suricata_scan.json")), "suricata")
        with self.assertRaises(ValueError):
            detect_format("ini bukan log")

    def test_tricky_legit_urls_not_flagged(self):
        line = ('36.68.14.21 - - [21/Nov/2026:10:30:00 +0700] "GET /products?category=union&select=blue HTTP/1.1" '
                '200 10 "-" "Mozilla/5.0"')
        self.assertEqual(analyze(parse_text(line, "web", 2026).events, RULES), [])

    def test_double_encoded_traversal(self):
        line = ('1.2.3.4 - - [21/Nov/2026:10:30:00 +0700] "GET /f?x=%252e%252e%252fetc HTTP/1.1" '
                '200 10 "-" "Mozilla/5.0"')
        alerts = analyze(parse_text(line, "web", 2026).events, RULES)
        self.assertEqual({a.rule_id for a in alerts}, {"R05"})

    def test_whitelist_suppresses_alerts(self):
        alerts = alerts_for("auth_bruteforce.log", whitelist=[ATTACKER_A])
        self.assertEqual(rule_ids(alerts, ATTACKER_A), set())

    def test_wazuh_parser(self):
        rec = ('{"timestamp":"2026-11-21T10:00:00.000+0000","rule":{"level":12,"description":"Multiple auth failures",'
               '"mitre":{"id":["T1110"]}},"agent":{"name":"web01"},"data":{"srcip":"5.5.5.5"}}')
        alerts = analyze(parse_text(rec, "auto", 2026).events, RULES)
        self.assertEqual(len(alerts), 1)
        self.assertEqual((alerts[0].severity, alerts[0].mitre), ("Critical", ["T1110"]))


class ApiFlow(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = create_app({"TESTING": True, "DB_PATH": os.path.join(self.tmp.name, "t.db"), "LOG_YEAR": 2026})
        self.client = self.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    def _upload(self, *names):
        data = {"file": [(io.BytesIO(sample(n).encode()), n) for n in names]}
        return self.client.post("/api/upload", data=data, content_type="multipart/form-data")

    def test_upload_summary_incidents_report(self):
        r = self._upload("auth_bruteforce.log", "web_attacks.log", "suricata_scan.json")
        self.assertEqual(r.status_code, 201)
        self.assertEqual(sorted(r.json["formats"]), ["ssh", "suricata", "web"])
        s = self.client.get("/api/summary").json
        self.assertGreater(s["severity_counts"]["Critical"], 0)
        inc = self.client.get("/api/incidents").json
        self.assertEqual(inc[0]["src_ip"], ATTACKER_A)
        self.assertIn("Critical", inc[0]["severity"])
        md = self.client.get("/api/report.md")
        self.assertIn(ATTACKER_A, md.get_data(as_text=True))
        self.assertEqual(self.client.get("/report").status_code, 200)

    def test_status_update_and_filters(self):
        self._upload("web_attacks.log")
        alerts = self.client.get("/api/alerts?severity=High").json
        self.assertTrue(alerts and all(a["severity"] == "High" for a in alerts))
        aid = alerts[0]["id"]
        self.assertEqual(self.client.patch(f"/api/alerts/{aid}", json={"status": "True Positive"}).status_code, 200)
        self.assertEqual(self.client.patch(f"/api/alerts/{aid}", json={"status": "hack"}).status_code, 400)
        self.assertEqual(len(self.client.get("/api/alerts?status=True+Positive").json), 1)

    def test_whitelist_api_and_validation(self):
        self.assertEqual(self.client.post("/api/whitelist", json={"ip": "not-an-ip"}).status_code, 400)
        self.assertEqual(self.client.post("/api/whitelist", json={"ip": ATTACKER_A}).status_code, 201)
        r = self._upload("auth_bruteforce.log")
        self.assertEqual(r.json["alerts"], 0)
        self.assertGreater(r.json["whitelisted_events"], 0)

    def test_bad_input_is_rejected_cleanly(self):
        self.assertEqual(self.client.post("/api/upload", data={}).status_code, 400)
        bad = {"file": [(io.BytesIO(b"bukan log sama sekali"), "x.log")]}
        r = self.client.post("/api/upload", data=bad, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 400)
        self.assertEqual(self.client.get("/api/alerts?severity=%27%20OR%201=1").status_code, 400)

    def test_scenario_endpoint(self):
        for key in "12345":
            self.assertEqual(self.client.post("/api/analyze-scenario", json={"key": key}).status_code, 201)
        self.assertEqual(self.client.post("/api/analyze-scenario", json={"key": "../../etc/passwd"}).status_code, 400)

    def test_explain_disabled_by_default(self):
        self._upload("web_attacks.log")
        self.assertFalse(self.client.post("/api/explain", json={"ip": ATTACKER_A}).json["enabled"])


if __name__ == "__main__":
    unittest.main()
