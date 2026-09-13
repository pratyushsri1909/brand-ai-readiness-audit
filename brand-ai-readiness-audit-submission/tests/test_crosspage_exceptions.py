import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch
import json

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("run_audit", ROOT / "skills/audit-orchestrator/scripts/run_audit.py")
run_audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(run_audit)

# mock socket for .test domains
import socket
if not hasattr(socket, '_real_c_getaddrinfo'):
    socket._real_c_getaddrinfo = socket.getaddrinfo
def _fake_getaddrinfo(host, port, *args, **kwargs):
    if host and (host.endswith('.test') or host.endswith('.example') or host.endswith('.invalid')):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', port or 0))]
    return socket._real_c_getaddrinfo(host, port, *args, **kwargs)
socket.getaddrinfo = _fake_getaddrinfo

class MockResponse:
    def __init__(self, text="", status=200, url="https://site.test/page", headers=None):
        self.text = text
        self.status = status
        self.url = url
        self.headers = headers or {}
    def read(self, n=-1): return self.text.encode()
    def getcode(self): return self.status
    def geturl(self): return self.url
    def __enter__(self): return self
    def __exit__(self, *args): pass

class TestCrossPageExceptions(unittest.TestCase):
    def run_with(self, robots, page=None):
        responses = []
        if isinstance(robots, Exception):
            responses.append(robots)
        else:
            responses.append(MockResponse(robots, 200, "https://site.test/robots.txt"))
        if page is not None:
            responses.append(page)
        with patch.object(run_audit, "_open_url", side_effect=responses) as mocked:
            result = run_audit.run_pipeline("https://site.test/page", enhanced=True)
        return result, mocked

    def test_entity_corroboration_exception(self):
        page_html = '<html><head><title>T</title></head><body><h1>T</h1><a href="/next">Next</a></body></html>'
        
        with patch.object(run_audit.entity_detector, "audit", return_value={"findings": []}):
            baseline, _ = self.run_with("User-agent: *\nAllow: /", MockResponse(page_html))
        baseline_findings = len(baseline["findings"])
        baseline_severity = dict(baseline["summary"])

        with patch.object(run_audit.entity_detector, "audit", side_effect=Exception("Entity mock crash")):
            result, _ = self.run_with("User-agent: *\nAllow: /", MockResponse(page_html))
        
        self.assertIn("analysis_status", result)
        has_incomplete = any(st.get("rule_id") == "CR-DETECTOR-INCOMPLETE-001" for st in result["analysis_status"])
        self.assertTrue(has_incomplete)
        
        has_incomplete_finding = any(f.get("rule_id") == "CR-DETECTOR-INCOMPLETE-001" for f in result["findings"])
        self.assertFalse(has_incomplete_finding)
        
        self.assertEqual(len(result["findings"]), baseline_findings)
        self.assertEqual(result["summary"]["critical"], baseline_severity["critical"])
        self.assertEqual(result["summary"]["high"], baseline_severity["high"])
        self.assertEqual(result["summary"]["medium"], baseline_severity["medium"])

    def test_content_quality_exception(self):
        page_html = '<html><head><title>T</title></head><body><h1>T</h1><a href="/next">Next</a></body></html>'
        
        with patch.object(run_audit.content_quality_detector, "audit", return_value={"findings": []}):
            baseline, _ = self.run_with("User-agent: *\nAllow: /", MockResponse(page_html))
        baseline_findings = len(baseline["findings"])
        baseline_severity = dict(baseline["summary"])

        with patch.object(run_audit.content_quality_detector, "audit", side_effect=Exception("CQ mock crash")):
            result, _ = self.run_with("User-agent: *\nAllow: /", MockResponse(page_html))
        
        self.assertIn("analysis_status", result)
        has_incomplete = any(st.get("rule_id") == "CR-DETECTOR-INCOMPLETE-001" for st in result["analysis_status"])
        self.assertTrue(has_incomplete)
        
        has_incomplete_finding = any(f.get("rule_id") == "CR-DETECTOR-INCOMPLETE-001" for f in result["findings"])
        self.assertFalse(has_incomplete_finding)
        
        self.assertEqual(len(result["findings"]), baseline_findings)
        self.assertEqual(result["summary"]["critical"], baseline_severity["critical"])
        self.assertEqual(result["summary"]["high"], baseline_severity["high"])
        self.assertEqual(result["summary"]["medium"], baseline_severity["medium"])

if __name__ == "__main__":
    unittest.main()
