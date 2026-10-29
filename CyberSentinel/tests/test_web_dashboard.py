"""
tests/test_web_dashboard.py — CyberSentinel Web Interface & API Test Suite
=============================================================================
National Cyber Threat Intelligence & Risk Analytics Platform

Verifies that the Flask web application, static assets, templates, and all
REST API endpoints function correctly with zero errors.
"""

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app import app


class TestWebDashboard(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config["TESTING"] = True
        cls.client = app.test_client()

    def test_01_index_html(self):
        """Test that the main dashboard HTML template renders successfully."""
        res = self.client.get("/")
        self.assertEqual(res.status_code, 200)
        html = res.data.decode("utf-8")
        self.assertIn("CYBERSENTINEL", html)
        self.assertIn("page-overview", html)
        self.assertIn("page-sectors", html)
        self.assertIn("page-threats", html)
        self.assertIn("page-vulnerabilities", html)
        self.assertIn("page-risk-analysis", html)
        self.assertIn("Academic Model", html)

    def test_02_api_overview(self):
        """Test /api/overview returns NCRI, KPI metrics, trends, and findings."""
        res = self.client.get("/api/overview")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("ncri", data)
        self.assertIn("score", data["ncri"])
        self.assertGreater(data["ncri"]["score"], 0)
        self.assertIn("vuln_metrics", data)
        self.assertIn("monthly_trends", data)
        self.assertGreater(len(data["monthly_trends"]), 0)
        self.assertIn("threat_distribution", data)
        self.assertIn("recent_records", data)
        self.assertIn("findings", data)

    def test_03_api_sectors(self):
        """Test /api/sectors returns sector risk scores and breakdown."""
        res = self.client.get("/api/sectors")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("sectors", data)
        self.assertGreaterEqual(len(data["sectors"]), 7)
        first_sector = data["sectors"][0]
        self.assertIn("acrs_score", first_sector)
        self.assertIn("nifs_score", first_sector)
        self.assertIn("wss_score", first_sector)
        self.assertIn("risk_category", first_sector)

    def test_04_api_threats(self):
        """Test /api/threats returns threat vectors and severity distribution."""
        res = self.client.get("/api/threats")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("threat_distribution", data)
        self.assertIn("threat_risk_scores", data)
        self.assertIn("severity_distribution", data)

    def test_05_api_vulnerabilities(self):
        """Test /api/vulnerabilities returns CVSS and KEV statistics."""
        res = self.client.get("/api/vulnerabilities")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("statistics", data)
        self.assertIn("severity_summary", data)
        self.assertIn("kev_summary", data)
        self.assertIn("score_distribution", data)

    def test_06_api_vulnerabilities_list_pagination(self):
        """Test /api/vulnerabilities/list paginated search and filters."""
        res = self.client.get("/api/vulnerabilities/list?page=1&per_page=10")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(len(data["records"]), 10)
        self.assertGreater(data["total_records"], 1000)

        # Test filter by severity
        res_crit = self.client.get("/api/vulnerabilities/list?severity=Critical&per_page=5")
        self.assertEqual(res_crit.status_code, 200)
        data_crit = res_crit.get_json()
        self.assertEqual(data_crit["status"], "success")
        for r in data_crit["records"]:
            self.assertEqual(r["cvss_severity"], "Critical")

        # Test filter by KEV exploitation
        res_kev = self.client.get("/api/vulnerabilities/list?exploited=1&per_page=5")
        self.assertEqual(res_kev.status_code, 200)
        data_kev = res_kev.get_json()
        self.assertEqual(data_kev["status"], "success")
        for r in data_kev["records"]:
            self.assertEqual(r["is_known_exploited"], 1)

    def test_07_api_incidents_list_pagination(self):
        """Test /api/incidents/list paginated search and filters."""
        res = self.client.get("/api/incidents/list?page=1&per_page=10")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(len(data["records"]), 10)
        self.assertGreater(data["total_records"], 2000)

        # Test filter by sector
        res_sec = self.client.get("/api/incidents/list?sector=Healthcare&per_page=5")
        self.assertEqual(res_sec.status_code, 200)
        data_sec = res_sec.get_json()
        self.assertEqual(data_sec["status"], "success")
        for r in data_sec["records"]:
            self.assertEqual(r["target_sector"], "Healthcare")

    def test_08_api_risk_analysis(self):
        """Test /api/risk-analysis returns approved formulas and insights."""
        res = self.client.get("/api/risk-analysis")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "success")
        self.assertIn("formula_documentation", data)
        self.assertIn("acrs_formula", data["formula_documentation"])
        self.assertIn("ncri_formula", data["formula_documentation"])
        self.assertIn("insights", data)

    def test_09_api_system_status(self):
        """Test /api/system-status returns database connectivity and table counts."""
        res = self.client.get("/api/system-status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["status"], "online")
        self.assertIn("database", data)
        self.assertGreater(data["database"]["counts"]["INCIDENTS"], 0)
        self.assertGreater(data["database"]["counts"]["VULNERABILITIES"], 0)


if __name__ == "__main__":
    unittest.main()
