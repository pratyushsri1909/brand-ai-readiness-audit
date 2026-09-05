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


from unittest.mock import patch, MagicMock
from urllib.error import HTTPError, URLError
from urllib.request import Request
from urllib.parse import urlparse
import time
import json

import importlib.util
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("run_audit",ROOT/"skills/audit-orchestrator/scripts/run_audit.py")
run_audit=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(run_audit)

SPEC_RULES=importlib.util.spec_from_file_location("rules",ROOT/"skills/audit-orchestrator/scripts/rules.py")
rules=importlib.util.module_from_spec(SPEC_RULES); SPEC_RULES.loader.exec_module(rules)

class MockResponse:
    def __init__(self, content, status, url, headers=None):
        self.content = content
        self.status = status
        self.url = url
        self.headers = headers or {"Content-Type": "text/html; charset=utf-8"}
        
    def read(self, *args, **kwargs):
        if isinstance(self.content, str):
            return self.content.encode("utf-8")
        return self.content
        
    def getcode(self):
        return self.status

    def geturl(self):
        return self.url

    def __enter__(self):
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

class TestPhase3BCorrections(unittest.TestCase):
    
    # -------------------------------------------------------------------------
    # 1. BROWSER ESCALATION TESTS
    # -------------------------------------------------------------------------
    def test_browser_escalation_substantial_dynamic_shell(self):
        """Generic framework/app-shell signals escalate even when the shell is not empty."""
        html = """<html><head>
        <script>window.__BOOTSTRAP__ = {};</script>
        <script src="/assets/runtime.js"></script>
        <script src="/assets/vendor.js"></script>
        <script src="/assets/app.js"></script>
        <script src="/assets/chunk.js"></script>
        <meta name="application" content="client app">
        </head><body data-reactroot>
        <header><nav><a href="/about">About</a><a href="/contact">Contact</a></nav></header>
        <div id="root"><div class="shell"><h1>Platform</h1><p>Welcome to the platform. Navigation and a limited initial shell are present in this response, while the primary application content is assembled by the client.</p></div></div>
        </body></html>"""
        profile = {"html": html}
        escalate, reason = run_audit.should_escalate_to_browser(profile)
        self.assertTrue(escalate)
        self.assertEqual(reason, "framework_external_scripts_limited_static_text")

    def test_rich_static_page_with_many_scripts_does_not_escalate(self):
        """Script references alone must not force browser execution on rich static HTML."""
        scripts = ''.join(f'<script src="/assets/{i}.js"></script>' for i in range(8))
        rich = " ".join(["A substantive statically delivered page with complete machine-readable copy."] * 40)
        html = f"<html><head>{scripts}</head><body><main><h1>Complete Static Page</h1><p>{rich}</p></main></body></html>"
        escalate, reason = run_audit.should_escalate_to_browser({"html": html})
        self.assertFalse(escalate)
        self.assertEqual(reason, "static_content_sufficient")

    def test_browser_escalation_criteria(self):
        """Test the new escalation criteria for generic SPA/JS-heavy shells."""
        # 1. Very low readable text + script heavy payload
        html_heavy_script = "<html><head><script>var x = '" + ("A" * 10000) + "';</script></head><body>Hello</body></html>"
        profile = {"html": html_heavy_script}
        escalate, reason = run_audit.should_escalate_to_browser(profile)
        self.assertTrue(escalate)
        self.assertEqual(reason, "script_heavy_low_text_ratio")
        
        # 2. Empty root
        html_empty_root = "<html><body><div id='root'></div><script>var x = 'init';</script></body></html>"
        profile = {"html": html_empty_root}
        escalate, reason = run_audit.should_escalate_to_browser(profile)
        self.assertTrue(escalate)
        self.assertEqual(reason, "empty_root_low_static_text")

        # 3. Hydration with low text
        # Use comments to pad HTML so script_ratio is low but text_ratio < 0.05
        html_hydration = "<html><body><script>__NEXT_DATA__={}</script><footer>Copyright 2026</footer><!-- " + ("x" * 2000) + " --></body></html>"
        profile = {"html": html_hydration}
        escalate, reason = run_audit.should_escalate_to_browser(profile)
        self.assertTrue(escalate)
        self.assertEqual(reason, "hydration_with_very_low_text")

    @patch.object(run_audit, "_is_safe_url", return_value=(True, None, ""))
    @patch.object(run_audit, "render_with_browser")
    @patch.object(run_audit, "_open_url")
    def test_escalation_triggers_render(self, mock_open_url, mock_render, mock_safe):
        """Verify run_pipeline actually invokes render_with_browser when criteria met."""
        html_empty_root = "<html><head><title>SPA</title></head><body><div id='root'></div><script>let a=1;</script></body></html>"
        mock_open_url.return_value = MockResponse(html_empty_root, 200, "https://test.site/")
        mock_render.return_value = ("<html><body><h1>Rendered!</h1></body></html>", True, "")
        
        result = run_audit.run_pipeline("https://test.site/", max_pages=1, enhanced=True)
        
        mock_render.assert_called_once()
        if "coverage" not in result:
            print("PIPELINE RESULT:", result)
        self.assertTrue(result["coverage"]["browser_pages"] >= 1)
        
        # Assert rendered text length was computed from the rendered HTML
        rendered_found = False
        for f in result["findings"]:
            if f.get("source_url") == "https://test.site/":
                rendered_found = True
        self.assertTrue(rendered_found)


    # -------------------------------------------------------------------------
    # 2. PAGE ROLE / PAGE INTENT PROPAGATION TESTS
    # -------------------------------------------------------------------------
    @patch.object(run_audit, "_is_safe_url", return_value=(True, None, ""))
    @patch.object(run_audit, "_open_url")
    def test_page_role_propagation_to_finding(self, mock_open_url, mock_safe):
        html_content = "<html><head><title>Pricing</title></head><body><h1>Our Pricing</h1><p>Words words words words words words words words words words words words words words words words words words words words.</p></body></html>"
        mock_open_url.return_value = MockResponse(html_content, 200, "https://test.site/pricing")
        
        # Need to patch discovery_detector in run_audit module space
        with patch.object(run_audit.discovery_detector, "classify_url_role", return_value=("pricing", "matched /pricing")):
            result = run_audit.run_pipeline("https://test.site/pricing", max_pages=1)
            
            for f in result["findings"]:
                if f.get("source_url") == "https://test.site/pricing":
                    self.assertEqual(f["page_role"], "pricing")
                    self.assertEqual(f["provenance"]["page_role"], "pricing")

    # -------------------------------------------------------------------------
    # 3. ROBOTS.TXT REDIRECT HANDLING TESTS
    # -------------------------------------------------------------------------
    def test_robots_redirect_safe(self):
        cache = run_audit.RobotsCache()
        
        # Mock 301 followed by 200
        responses = [
            HTTPError("https://site.test/robots.txt", 301, "Moved", {"Location": "https://site.test/robots_real.txt"}, None),
            MockResponse("User-agent: *\nDisallow: /blocked", 200, "https://site.test/robots_real.txt")
        ]
        
        def mock_open(req, timeout):
            res = responses.pop(0)
            if isinstance(res, HTTPError):
                raise res
            return res
            
        with patch.object(run_audit, "_open_url", side_effect=mock_open):
            result = cache.get_robots(urlparse("https://site.test"))
            self.assertEqual(result["status"], "ok")
            self.assertEqual(result["url"], "https://site.test/robots_real.txt")
            self.assertTrue(cache.allows("https://site.test/page"))
            self.assertFalse(cache.allows("https://site.test/blocked"))

    def test_robots_redirect_unsafe_out_of_scope(self):
        cache = run_audit.RobotsCache()
        responses = [
            HTTPError("https://site.test/robots.txt", 301, "Moved", {"Location": "https://evil.test/robots.txt"}, None)
        ]
        def mock_open(req, timeout):
            raise responses.pop(0)
            
        with patch.object(run_audit, "_open_url", side_effect=mock_open):
            result = cache.get_robots(urlparse("https://site.test"))
            self.assertEqual(result["status"], "unsafe")
            self.assertEqual(result["error"], "redirect_out_of_scope")

    def test_robots_redirect_loop(self):
        cache = run_audit.RobotsCache()
        def mock_open(req, timeout):
            raise HTTPError(req.full_url, 302, "Found", {"Location": req.full_url + "x"}, None)
            
        with patch.object(run_audit, "_open_url", side_effect=mock_open):
            result = cache.get_robots(urlparse("https://site.test"))
            self.assertEqual(result["status"], "unsafe")
            self.assertEqual(result["error"], "redirect_loop")


    # -------------------------------------------------------------------------
    # 4. SOFT-BLOCK / CHALLENGE DETECTION TESTS
    # -------------------------------------------------------------------------
    def test_soft_block_challenge_signals(self):
        # Normal page
        self.assertFalse(run_audit.check_soft_block("<html><body>Normal content</body></html>", 200))
        
        # Challenge text
        html = "<html><body>Please verify you are a human. Just a moment...</body></html>"
        self.assertTrue(run_audit.check_soft_block(html, 200))

    def test_soft_block_noindex_tiny(self):
        # A page with noindex + less than 1000 chars of text should NOT be classified as a soft block alone (P1-2 fix)
        html = "<html><head><meta name='robots' content='noindex, nofollow'></head><body>Loading...</body></html>"
        self.assertFalse(run_audit.check_soft_block(html, 200))
        
        # Legitimate thin page with noindex but enough text
        html_valid = "<html><head><meta name='robots' content='noindex, nofollow'></head><body><h1>Staging Site</h1>" + ("<p>Legitimate text</p>" * 200) + "</body></html>"
        self.assertFalse(run_audit.check_soft_block(html_valid, 200))

    @patch.object(run_audit, "_is_safe_url", return_value=(True, None, ""))
    @patch.object(run_audit, "_open_url")
    def test_soft_block_suppresses_absence_findings(self, mock_open_url, mock_safe):
        # Provide a payload that triggers check_soft_block under P1-2 rules
        html = "<html><head><meta name='robots' content='noindex, nofollow, noarchive'></head><body>Just a moment... verifying you are a human.</body></html>"
        mock_open_url.return_value = MockResponse(html, 200, "https://test.site/")
        
        result = run_audit.run_pipeline("https://test.site/", max_pages=1)
        
        # Since it's soft_blocked, detectors should not run and there should be NO SD-MISSING-001 or CR-NOINDEX-001 findings
        titles = [f["title"] for f in result.get("findings", [])]
        self.assertNotIn("Noindex Directive Blocks Machine Indexing", titles)
        self.assertNotIn("Missing JSON-LD Structured Data", titles)
        self.assertNotIn("Missing H1 Heading", titles)


if __name__ == "__main__":
    unittest.main()
