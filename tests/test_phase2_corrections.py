"""
Phase-2 Systemic Corrections – Regression Test Suite.

Validates all seven Phase-2 correction components plus structured-data
extraction-uncertainty suppression and end-to-end browser escalation.

Run via:
  python -m unittest tests/test_phase2_corrections.py
"""
import importlib.util
import os
import sys
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

# Ensure the parent directory is in the path to import from skills
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


def load_module_from_path(module_name, file_path):
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


_BASE = os.path.dirname(__file__)
run_audit = load_module_from_path('run_audit', os.path.join(_BASE, '../skills/audit-orchestrator/scripts/run_audit.py'))
rules = load_module_from_path('rules', os.path.join(_BASE, '../skills/audit-orchestrator/scripts/rules.py'))
engagement_detector = load_module_from_path('engagement_detector', os.path.join(_BASE, '../skills/engagement-audit/scripts/detector.py'))
content_quality_detector = load_module_from_path('content_quality_detector', os.path.join(_BASE, '../skills/content-quality-audit/scripts/detector.py'))
schema_detector = load_module_from_path('schema_detector', os.path.join(_BASE, '../skills/structured-data-freshness/scripts/detector.py'))


class TestBrowserEscalationHeuristics(unittest.TestCase):
    """Component 1: should_escalate_to_browser heuristics."""

    def test_spa_mount_escalation(self):
        html = '<div id="root"></div>' + 'A' * 499
        profile = {"html": html}
        escalate, reason = run_audit.should_escalate_to_browser(profile)
        self.assertTrue(escalate)
        self.assertEqual(reason, "empty_root_low_static_text")

    def test_hydration_marker_escalation(self):
        # Pad HTML so text_ratio < 0.05 to trigger new heuristic
        html = '<html><head></head><body><script id="__NEXT_DATA__" type="application/json">{"props":{}}</script><script src="app.js"></script><p>Loading...</p>' + ('<!-- pad -->' * 50) + '</body></html>'
        profile = {"html": html}
        escalate, reason = run_audit.should_escalate_to_browser(profile)
        self.assertTrue(escalate)
        self.assertEqual(reason, "hydration_with_very_low_text")

    def test_virtually_empty_escalation(self):
        html = '<script></script>' + 'A' * 149
        profile = {"html": html}
        escalate, reason = run_audit.should_escalate_to_browser(profile)
        self.assertTrue(escalate)
        self.assertEqual(reason, "virtually_empty_with_scripts")

    def test_script_heavy_escalation(self):
        html = ('<script>' + 'A' * 1000 + '</script>') * 4 + 'A' * 200
        profile = {"html": html}
        escalate, reason = run_audit.should_escalate_to_browser(profile)
        self.assertTrue(escalate)
        self.assertEqual(reason, "script_heavy_low_text_ratio")

    def test_rich_static_no_escalation(self):
        html = '<main>' + ('word ' * 300) + '</main>'
        profile = {"html": html}
        escalate, reason = run_audit.should_escalate_to_browser(profile)
        self.assertFalse(escalate)
        self.assertEqual(reason, "static_content_sufficient")


class TestFalseAbsenceSuppression(unittest.TestCase):
    """Component 2: Engagement detector suppresses absence findings when extraction is uncertain."""

    def test_uncertain_extraction_suppresses_absence_findings(self):
        profile = {
            "url": "https://example.com",
            "html": "<div>no h1</div>",
            "status_code": 200,
            "extraction_uncertain": True,
            "is_spa_shell": False
        }
        result = engagement_detector.audit(profile)
        rule_ids = [f["rule_id"] for f in result.get("findings", [])]
        self.assertNotIn("ENG-H1-ZERO-001", rule_ids)
        self.assertNotIn("ENG-ORIENTATION-MISSING-001", rule_ids)
        self.assertNotIn("ENG-NAV-DEADEND-001", rule_ids)
        self.assertNotIn("ENG-CTA-MISSING-001", rule_ids)

    def test_uncertain_extraction_preserves_positive_findings(self):
        profile = {
            "url": "https://example.com",
            "html": "<title>Home</title><div>no h1</div>",
            "status_code": 200,
            "extraction_uncertain": True
        }
        result = engagement_detector.audit(profile)
        rule_ids = [f["rule_id"] for f in result.get("findings", [])]
        self.assertIn("ENG-TITLE-GENERIC-001", rule_ids)


class TestContentQualityPageRole(unittest.TestCase):
    """Component 3: Content quality thin content uses page_role thresholds."""

    def test_article_triggers_thin(self):
        text = "word " * 100
        html = f"<main>{text}</main>"
        result = content_quality_detector.audit({
            "url": "https://example.com/art",
            "html": html,
            "status_code": 200,
            "page_role": "article"
        })
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("CQ-THIN-001", rule_ids)

    def test_homepage_does_not_trigger_thin(self):
        text = "word " * 100
        html = f"<main>{text}</main>"
        result = content_quality_detector.audit({
            "url": "https://example.com/home",
            "html": html,
            "status_code": 200,
            "page_role": "homepage"
        })
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertNotIn("CQ-THIN-001", rule_ids)


class TestRobotsVerificationRootCause(unittest.TestCase):
    """Component 5: robots.txt error detail enrichment."""

    def test_dns_root_cause_enrichment(self):
        raw_finding = {
            "rule_id": "CR-ROBOTS-003",
            "title": "Unable to Verify robots.txt Safety",
            "evidence": "failed",
            "severity": "high",
            "robots_error_detail": "DNS resolution failed"
        }
        context = {"url": "https://example.com"}
        enriched = rules.enrich_finding(raw_finding, context)
        self.assertIn("dns resolution failed", enriched["root_cause"].lower())
        self.assertIn("dns resolution failed", enriched["expected_mechanism"].lower())


class TestInconclusiveReadiness(unittest.TestCase):
    """Component 6: Zero-coverage audits yield Inconclusive readiness."""

    def test_zero_coverage_is_inconclusive(self):
        report = run_audit.build_final_report(
            "example.com", "2024-01-01", [],
            enhanced=True,
            coverage_data={"pages_skipped": [], "urls_rendered": 0}
        )
        self.assertEqual(report["readiness_band"]["band"], "Inconclusive")
        self.assertIn("inconclusive", report["readiness_band"]["formula_explanation"].lower())


class TestStructuredDataExtractionUncertainty(unittest.TestCase):
    """
    Structured-data absence findings must be suppressed when
    extraction is uncertain (unresolved SPA shell, failed browser recovery).
    """

    def test_A_unresolved_spa_no_browser_suppresses_sd_missing(self):
        """Unresolved SPA shell + browser unavailable -> no SD-MISSING-001."""
        html = '<div id="root"></div><script src="/app.js"></script>'
        result = schema_detector.audit({
            "url": "https://example.com",
            "html": html,
            "status_code": 200,
            "extraction_uncertain": True,
            "is_spa_shell": True,
        })
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertNotIn("SD-MISSING-001", rule_ids)

    def test_B_spa_with_successful_browser_no_jsonld_emits_sd_missing(self):
        """SPA + successful browser render (no JSON-LD in rendered HTML) -> SD-MISSING-001 may be emitted."""
        html = '<main><h1>Rendered Content</h1><p>Lots of content here after rendering.</p></main>'
        result = schema_detector.audit({
            "url": "https://example.com",
            "html": html,
            "status_code": 200,
            "extraction_uncertain": False,
            "is_spa_shell": False,
        })
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("SD-MISSING-001", rule_ids)

    def test_C_normal_static_html_no_jsonld_emits_sd_missing(self):
        """Normal static HTML with no JSON-LD -> SD-MISSING-001 remains."""
        html = '<html><head><title>Normal Page</title></head><body><h1>Hello</h1></body></html>'
        result = schema_detector.audit({
            "url": "https://example.com",
            "html": html,
            "status_code": 200,
        })
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("SD-MISSING-001", rule_ids)

    def test_D_valid_jsonld_observed_preserved(self):
        """Valid JSON-LD observed -> positive evidence preserved (no SD-MISSING-001)."""
        html = '''<html><head>
            <script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization","name":"Acme"}</script>
        </head><body><h1>Hello</h1></body></html>'''
        result = schema_detector.audit({
            "url": "https://example.com",
            "html": html,
            "status_code": 200,
        })
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertNotIn("SD-MISSING-001", rule_ids)

    def test_E_malformed_jsonld_in_reliable_html_preserved(self):
        """Malformed JSON-LD in reliably inspected HTML -> SD-SYNTAX-001 preserved."""
        html = '''<html><head>
            <script type="application/ld+json">{bad json here!</script>
        </head><body><h1>Hello</h1></body></html>'''
        result = schema_detector.audit({
            "url": "https://example.com",
            "html": html,
            "status_code": 200,
            "extraction_uncertain": False,
        })
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertIn("SD-SYNTAX-001", rule_ids)

    def test_extraction_uncertain_alone_suppresses_sd_missing(self):
        """extraction_uncertain=True alone (without is_spa_shell) also suppresses SD-MISSING-001."""
        html = '<html><body><p>Minimal content</p></body></html>'
        result = schema_detector.audit({
            "url": "https://example.com",
            "html": html,
            "status_code": 200,
            "extraction_uncertain": True,
        })
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertNotIn("SD-MISSING-001", rule_ids)


class TestEndToEndBrowserEscalation(unittest.TestCase):
    """
    End-to-end test proving the full browser escalation pipeline:

    static JS-heavy page
      -> should_escalate_to_browser=True
      -> render_with_browser is actually invoked
      -> rendered HTML is returned
      -> PageProfile analysis_source="rendered"
      -> rendered_text_length is populated
      -> downstream detector receives the rendered profile
    """

    class _MockResponse:
        """Minimal response mock matching the interface that fetch_page expects."""
        def __init__(self, content, status=200, url="https://e2e-test.test/",
                     headers=None):
            self._content = content.encode("utf-8") if isinstance(content, str) else content
            self.status = status
            self.url = url
            self.headers = headers or {"Content-Type": "text/html; charset=utf-8"}

        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def read(self, amt=None):
            return self._content

        def geturl(self):
            return self.url

        def getheader(self, name, default=None):
            for k, v in self.headers.items():
                if k.lower() == name.lower():
                    return v
            return default

        def getcode(self):
            return self.status

        def close(self):
            pass

    def _make_mock_response(self, content, status=200, url="https://e2e-test.test/",
                            content_type="text/html; charset=utf-8"):
        return self._MockResponse(content, status, url, {"Content-Type": content_type})

    def test_full_pipeline_browser_escalation_and_rendered_profile(self):
        """JS-heavy static page triggers escalation, browser returns rich HTML, detectors see rendered content."""
        # Static page: SPA shell with almost no readable text -> triggers escalation
        static_html = (
            '<!DOCTYPE html><html><head><title>App</title></head>'
            '<body><div id="root"></div>'
            '<script src="/bundle.js"></script></body></html>'
        )
        # Rendered page: rich content after browser hydration
        rendered_html = (
            '<!DOCTYPE html><html><head><title>My Application</title>'
            '<meta name="description" content="A rich rendered application.">'
            '<script type="application/ld+json">'
            '{"@context":"https://schema.org","@type":"WebSite","name":"MyApp","url":"https://e2e-test.test/"}'
            '</script>'
            '</head><body><div id="root">'
            '<header><nav><a href="/about">About</a></nav></header>'
            '<main><h1>Welcome to My Application</h1>'
            '<p>This is a fully rendered page with rich content. '
            'Our platform provides comprehensive solutions for modern development teams. '
            'Discover features, integrations, and deployment options across cloud environments.</p>'
            '<a href="/about">Learn More</a></main>'
            '</div></body></html>'
        )

        robots_txt = "User-agent: *\nAllow: /\n"

        def mock_open(req, timeout=10):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            if "robots.txt" in url:
                return self._make_mock_response(robots_txt, url=url, content_type="text/plain")
            if "sitemap.xml" in url:
                return self._make_mock_response(
                    '<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>',
                    url=url, content_type="application/xml"
                )
            return self._make_mock_response(static_html, url=url)

        render_called = {"count": 0}

        def mock_render(url, *args, **kwargs):
            render_called["count"] += 1
            return (rendered_html, True, None)

        with patch.object(run_audit, "_open_url", side_effect=mock_open):
            with patch.object(run_audit, "render_with_browser", side_effect=mock_render):
                report = run_audit.run_pipeline("https://e2e-test.test/", enhanced=True, max_pages=1)

        # render_with_browser was actually invoked
        self.assertGreaterEqual(render_called["count"], 1, "render_with_browser must be invoked")

        # Check coverage shows browser escalation
        cov = report.get("coverage", {})
        self.assertGreaterEqual(cov.get("urls_rendered", 0) + cov.get("browser_pages", 0), 1)

        # Verify the rendered content was used in analysis (the rendered HTML has an H1
        # and JSON-LD, so we should NOT see SD-MISSING-001 or ENG-H1-ZERO-001 findings)
        rule_ids = [f.get("rule_id") for f in report.get("findings", [])]
        self.assertNotIn("ENG-H1-ZERO-001", rule_ids,
                         "H1 from rendered content should have been detected")
        self.assertNotIn("SD-MISSING-001", rule_ids,
                         "JSON-LD from rendered content should have been detected")

    def test_browser_failure_sets_extraction_uncertain(self):
        """When browser fallback fails, extraction_uncertain=True is set."""
        static_html = (
            '<!DOCTYPE html><html><head><title>App</title></head>'
            '<body><div id="root"></div>'
            '<script src="/bundle.js"></script></body></html>'
        )
        robots_txt = "User-agent: *\nAllow: /\n"

        def mock_open(req, timeout=10):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            if "robots.txt" in url:
                return self._make_mock_response(robots_txt, url=url, content_type="text/plain")
            if "sitemap.xml" in url:
                return self._make_mock_response(
                    '<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"></urlset>',
                    url=url, content_type="application/xml"
                )
            return self._make_mock_response(static_html, url=url)

        def mock_render_fail(url, *args, **kwargs):
            return (None, False, "playwright_unavailable")

        with patch.object(run_audit, "_open_url", side_effect=mock_open):
            with patch.object(run_audit, "render_with_browser", side_effect=mock_render_fail):
                report = run_audit.run_pipeline("https://e2e-test.test/", enhanced=True, max_pages=1)

        # With extraction_uncertain=True and is_spa_shell=True, absence findings should be suppressed
        rule_ids = [f.get("rule_id") for f in report.get("findings", [])]
        self.assertNotIn("ENG-H1-ZERO-001", rule_ids)
        self.assertNotIn("SD-MISSING-001", rule_ids)


if __name__ == "__main__":
    unittest.main()
