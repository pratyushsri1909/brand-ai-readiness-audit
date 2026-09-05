import importlib.util
import unittest

# global getaddrinfo mock for .test domains
import socket
if not hasattr(socket, '_real_c_getaddrinfo'):
    socket._real_c_getaddrinfo = socket.getaddrinfo
def _fake_getaddrinfo(host, port, *args, **kwargs):
    if host and (host.endswith('.test') or host.endswith('.example') or host.endswith('.invalid')):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('93.184.216.34', port or 0))]
    return socket._real_c_getaddrinfo(host, port, *args, **kwargs)
socket.getaddrinfo = _fake_getaddrinfo


from pathlib import Path
from unittest.mock import patch, MagicMock

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("run_audit",ROOT/"skills/audit-orchestrator/scripts/run_audit.py")
run_audit=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(run_audit)

class MockResponse:
    def __init__(self, content, status_code, url, headers=None):
        self.content = content
        self.status_code = status_code
        self.url = url
        self.headers = headers or {}
    
    def read(self, n=-1):
        return self.content.encode('utf-8')
    
    def getcode(self):
        return self.status_code
    
    def geturl(self):
        return self.url
    
    def info(self):
        return self.headers
    
    def __enter__(self): return self
    def __exit__(self,*args): return False
    
    def geturl(self):
        return self.url
    
    def info(self):
        return self.headers

class TestRedirectChainDetection(unittest.TestCase):
    def test_01_two_hop_chain(self):
        def mock_redirects(req, timeout=10):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            if url.endswith("/robots.txt"):
                return MockResponse("User-agent: *\nAllow: /\n", 200, url, {"Content-Type": "text/plain"})
            if url == "https://chain.test/A":
                return MockResponse("", 301, url, {"Location": "https://chain.test/B"})
            if url == "https://chain.test/B":
                return MockResponse("", 302, url, {"Location": "https://chain.test/C"})
            if url == "https://chain.test/C":
                return MockResponse("<!DOCTYPE html><html><head><title>C</title></head><body><h1>C</h1></body></html>", 200, url)
            return MockResponse("404", 404, url)

        with patch.object(run_audit, "_open_url", side_effect=mock_redirects):
            report = run_audit.run_pipeline("https://chain.test/A", enhanced=True, max_pages=3)
        
        findings = report.get("findings", [])
        rc_findings = [f for f in findings if f.get("rule_id") == "CR-REDIRECT-CHAIN-001"]
        self.assertEqual(len(rc_findings), 1)

    def test_02_three_hop_chain(self):
        def mock_redirects(req, timeout=10):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            if url.endswith("/robots.txt"):
                return MockResponse("User-agent: *\nAllow: /\n", 200, url, {"Content-Type": "text/plain"})
            if url == "https://chain.test/A":
                return MockResponse("", 301, url, {"Location": "https://chain.test/B"})
            if url == "https://chain.test/B":
                return MockResponse("", 302, url, {"Location": "https://chain.test/C"})
            if url == "https://chain.test/C":
                return MockResponse("", 302, url, {"Location": "https://chain.test/D"})
            if url == "https://chain.test/D":
                return MockResponse("<!DOCTYPE html><html><head><title>D</title></head><body><h1>D</h1></body></html>", 200, url)
            return MockResponse("404", 404, url)

        with patch.object(run_audit, "_open_url", side_effect=mock_redirects):
            report = run_audit.run_pipeline("https://chain.test/A", enhanced=True, max_pages=3)
        
        findings = report.get("findings", [])
        rc_findings = [f for f in findings if f.get("rule_id") == "CR-REDIRECT-CHAIN-001"]
        self.assertEqual(len(rc_findings), 1)

    def test_03_single_redirect_no_finding(self):
        def mock_redirects(req, timeout=10):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            if url.endswith("/robots.txt"):
                return MockResponse("User-agent: *\nAllow: /\n", 200, url, {"Content-Type": "text/plain"})
            if url == "https://chain.test/A":
                return MockResponse("", 301, url, {"Location": "https://chain.test/B"})
            if url == "https://chain.test/B":
                return MockResponse("<!DOCTYPE html><html><head><title>B</title></head><body><h1>B</h1></body></html>", 200, url)
            return MockResponse("404", 404, url)

        with patch.object(run_audit, "_open_url", side_effect=mock_redirects):
            report = run_audit.run_pipeline("https://chain.test/A", enhanced=True, max_pages=3)
        
        findings = report.get("findings", [])
        rc_findings = [f for f in findings if f.get("rule_id") == "CR-REDIRECT-CHAIN-001"]
        self.assertEqual(len(rc_findings), 0)

    def test_04_redirect_loop(self):
        def mock_redirects(req, timeout=10):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            if url.endswith("/robots.txt"):
                return MockResponse("User-agent: *\nAllow: /\n", 200, url, {"Content-Type": "text/plain"})
            if url == "https://chain.test/A":
                return MockResponse("", 301, url, {"Location": "https://chain.test/B"})
            if url == "https://chain.test/B":
                return MockResponse("", 301, url, {"Location": "https://chain.test/A"})
            return MockResponse("404", 404, url)

        with patch.object(run_audit, "_open_url", side_effect=mock_redirects):
            report = run_audit.run_pipeline("https://chain.test/A", enhanced=True, max_pages=3)
        
        findings = report.get("findings", [])
        rc_findings = [f for f in findings if f.get("rule_id") == "CR-REDIRECT-CHAIN-001"]
        self.assertTrue(len(rc_findings) >= 1)

    def test_05_external_out_of_scope(self):
        def mock_redirects(req, timeout=10):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            if url.endswith("/robots.txt"):
                return MockResponse("User-agent: *\nAllow: /\n", 200, url, {"Content-Type": "text/plain"})
            if url == "https://chain.test/A":
                return MockResponse("", 301, url, {"Location": "https://external.test/B"})
            return MockResponse("404", 404, url)

        with patch.object(run_audit, "_open_url", side_effect=mock_redirects):
            report = run_audit.run_pipeline("https://chain.test/A", enhanced=True, max_pages=3)
        
        findings = report.get("findings", [])
        rc_findings = [f for f in findings if f.get("rule_id") == "CR-REDIRECT-CHAIN-001"]
        self.assertEqual(len(rc_findings), 0)

    def test_06_ssrf_blocked_after_two_hops(self):
        def mock_redirects(req, timeout=10):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            if url.endswith("/robots.txt"):
                return MockResponse("User-agent: *\nAllow: /\n", 200, url, {"Content-Type": "text/plain"})
            if url == "https://chain.test/A":
                return MockResponse("", 301, url, {"Location": "https://chain.test/B"})
            if url == "https://chain.test/B":
                return MockResponse("", 301, url, {"Location": "http://169.254.169.254/meta"})
            return MockResponse("404", 404, url)

        with patch.object(run_audit, "_open_url", side_effect=mock_redirects):
            report = run_audit.run_pipeline("https://chain.test/A", enhanced=True, max_pages=3)
        
        findings = report.get("findings", [])
        rc_findings = [f for f in findings if f.get("rule_id") == "CR-REDIRECT-CHAIN-001"]
        self.assertEqual(len(rc_findings), 1)

    def test_07_robots_blocked(self):
        def mock_redirects(req, timeout=10):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            if url.endswith("/robots.txt"):
                return MockResponse("User-agent: *\nDisallow: /B\n", 200, url, {"Content-Type": "text/plain"})
            if url == "https://chain.test/A":
                return MockResponse("", 301, url, {"Location": "https://chain.test/B"})
            return MockResponse("404", 404, url)

        with patch.object(run_audit, "_open_url", side_effect=mock_redirects):
            report = run_audit.run_pipeline("https://chain.test/A", enhanced=True, max_pages=3)
        
        findings = report.get("findings", [])
        rc_findings = [f for f in findings if f.get("rule_id") == "CR-REDIRECT-CHAIN-001"]
        self.assertEqual(len(rc_findings), 0)

if __name__ == "__main__":
    unittest.main()
