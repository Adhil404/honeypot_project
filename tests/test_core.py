"""
tests/test_core.py — Unit tests for core modules.
Run with: python -m pytest tests/ -v
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest
from core.threat_analyser import ThreatAnalyser
from core.event_store import EventStore, ConnectionEvent
from config.settings import load_config, DEFAULTS
from datetime import datetime, timezone


class TestThreatAnalyser(unittest.TestCase):

    def setUp(self):
        self.config   = DEFAULTS
        self.analyser = ThreatAnalyser(self.config)

    def test_clean_request_is_low(self):
        r = self.analyser.analyse("10.0.0.1", "GET", "/products",
                                  {"User-Agent": "Mozilla/5.0"}, "")
        self.assertEqual(r.severity, "LOW")

    def test_sql_injection_detected(self):
        r = self.analyser.analyse("10.0.0.2", "GET",
                                  "/products?id=1 UNION SELECT * FROM users--",
                                  {"User-Agent": "Mozilla/5.0"}, "")
        self.assertIn("sql_injection", r.tags)
        self.assertGreaterEqual(r.score, 40)

    def test_xss_detected(self):
        r = self.analyser.analyse("10.0.0.3", "GET",
                                  "/search?q=<script>alert(1)</script>",
                                  {"User-Agent": "Mozilla/5.0"}, "")
        self.assertIn("xss_attempt", r.tags)

    def test_path_traversal_detected(self):
        r = self.analyser.analyse("10.0.0.4", "GET", "/files/../../../../etc/passwd",
                                  {"User-Agent": "Mozilla/5.0"}, "")
        self.assertIn("path_traversal", r.tags)

    def test_scanner_ua_detected(self):
        r = self.analyser.analyse("10.0.0.5", "GET", "/",
                                  {"User-Agent": "sqlmap/1.7.8"}, "")
        self.assertIn([t for t in r.tags if "scanner_ua" in t][0], r.tags)

    def test_credential_stuffing(self):
        r = self.analyser.analyse("10.0.0.6", "POST", "/login",
                                  {"User-Agent": "python-requests/2.28"}, "user=admin&pass=admin")
        self.assertIn("credential_stuffing_attempt", r.tags)

    def test_critical_severity(self):
        # Multiple overlapping attacks should hit CRITICAL
        r = self.analyser.analyse("10.0.0.7", "POST", "/login",
                                  {"User-Agent": "sqlmap/1.7"},
                                  "user=admin' OR 1=1-- &pass=x")
        self.assertIn(r.severity, ["HIGH", "CRITICAL"])


class TestEventStore(unittest.TestCase):

    def setUp(self):
        self.store = EventStore(log_dir="/tmp/honeypot_test_logs")

    def _make_event(self, ip="1.2.3.4", severity="LOW"):
        return ConnectionEvent(
            ip=ip, port=54321, service="Test", protocol="http",
            timestamp=datetime.now(timezone.utc).isoformat(),
            session_id="test-session-123", severity=severity,
        )

    def test_add_and_retrieve(self):
        e = self._make_event()
        self.store.add(e)
        recent = self.store.recent(10)
        self.assertGreater(len(recent), 0)
        self.assertEqual(recent[-1].ip, "1.2.3.4")

    def test_stats_count(self):
        for i in range(5):
            self.store.add(self._make_event(ip=f"10.0.0.{i}"))
        s = self.store.stats()
        self.assertGreaterEqual(s["total_events"], 5)
        self.assertGreaterEqual(s["unique_ips"], 5)

    def test_severity_stats(self):
        self.store.add(self._make_event(severity="CRITICAL"))
        self.store.add(self._make_event(severity="HIGH"))
        s = self.store.stats()
        self.assertGreaterEqual(s["critical_count"], 1)

    def test_top_ips(self):
        for _ in range(3):
            self.store.add(self._make_event(ip="9.9.9.9"))
        s = self.store.stats()
        ips = [x["ip"] for x in s["top_attacker_ips"]]
        self.assertIn("9.9.9.9", ips)

    def test_event_to_dict(self):
        e = self._make_event()
        d = e.to_dict()
        self.assertIn("ip", d)
        self.assertIn("timestamp", d)
        self.assertIn("session_id", d)


class TestConfig(unittest.TestCase):

    def test_defaults_load(self):
        cfg = load_config("nonexistent_file.json")
        self.assertIn("services", cfg)
        self.assertIn("dashboard", cfg)
        self.assertIn("threat_intel", cfg)

    def test_service_count(self):
        cfg = load_config("nonexistent_file.json")
        self.assertGreater(len(cfg["services"]), 0)

    def test_dashboard_port(self):
        cfg = load_config("nonexistent_file.json")
        self.assertEqual(cfg["dashboard"]["port"], 5000)


if __name__ == "__main__":
    unittest.main(verbosity=2)
