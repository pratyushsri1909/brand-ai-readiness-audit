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
from unittest.mock import patch
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[1]
SPEC_DISC = importlib.util.spec_from_file_location("discovery_detector", ROOT / "skills/site-discovery-audit/scripts/detector.py")
discovery = importlib.util.module_from_spec(SPEC_DISC)
SPEC_DISC.loader.exec_module(discovery)

SPEC_RUN = importlib.util.spec_from_file_location("run_audit", ROOT / "skills/audit-orchestrator/scripts/run_audit.py")
run_audit = importlib.util.module_from_spec(SPEC_RUN)
SPEC_RUN.loader.exec_module(run_audit)


class MockResponse:
    def __init__(self, text="", status=200, url="https://site.test/page", headers=None):
        self.text = text
        self.status = status
        self.url = url
        self.headers = headers or {}

    def read(self, n=-1):
        return self.text.encode()

    def getcode(self):
        return self.status

    def geturl(self):
        return self.url

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class TestCrawlerPredicateChain(unittest.TestCase):
    def test_scheme_predicate(self):
        valid, reason, _ = discovery.should_visit_url("ftp://site.test/file", base_url="https://site.test/")
        self.assertFalse(valid)
        self.assertEqual(reason, "unsupported_scheme")

    def test_host_predicate_rejects_external_domain(self):
        valid, reason, _ = discovery.should_visit_url("https://external.com/page", base_url="https://site.test/", target_host="site.test")
        self.assertFalse(valid)
        self.assertEqual(reason, "external_domain")

    def test_non_html_extensions_rejected(self):
        for ext in [".pdf", ".png", ".jpg", ".zip", ".exe", ".css", ".js", ".mp4"]:
            valid, reason, _ = discovery.should_visit_url(f"https://site.test/doc{ext}", base_url="https://site.test/")
            self.assertFalse(valid, f"Extension {ext} should be rejected")
            self.assertTrue(reason.startswith("non_html_extension"))

    def test_max_depth_ceiling(self):
        valid, reason, _ = discovery.should_visit_url("https://site.test/page", base_url="https://site.test/", depth=4, max_depth=3)
        self.assertFalse(valid)
        self.assertTrue(reason.startswith("max_depth_exceeded"))

    def test_query_parameter_explosion_trap(self):
        trap_url = "https://site.test/catalog?a=1&b=2&c=3&d=4&e=5"
        valid, reason, _ = discovery.should_visit_url(trap_url, base_url="https://site.test/")
        self.assertFalse(valid)
        self.assertEqual(reason, "query_parameter_explosion_trap")

    def test_search_or_filter_trap(self):
        valid, reason, _ = discovery.should_visit_url("https://site.test/search?q=shoes", base_url="https://site.test/")
        self.assertFalse(valid)
        self.assertEqual(reason, "search_or_filter_trap")

    def test_pagination_depth_trap(self):
        valid, reason, _ = discovery.should_visit_url("https://site.test/blog?page=50", base_url="https://site.test/")
        self.assertFalse(valid)
        self.assertEqual(reason, "pagination_depth_trap")

    def test_repeating_path_segment_trap(self):
        valid, reason, _ = discovery.should_visit_url("https://site.test/a/b/a/b/a/b", base_url="https://site.test/")
        self.assertFalse(valid)
        self.assertEqual(reason, "repeating_path_segment_trap")

    def test_calendar_date_trap(self):
        valid, reason, _ = discovery.should_visit_url("https://site.test/events/2024/05/01/item", base_url="https://site.test/")
        self.assertFalse(valid)
        self.assertEqual(reason, "calendar_date_trap")

    def test_duplicate_url_rejected(self):
        visited = {"https://site.test/visited-page"}
        valid, reason, _ = discovery.should_visit_url("https://site.test/visited-page", base_url="https://site.test/", visited_set=visited)
        self.assertFalse(valid)
        self.assertEqual(reason, "already_visited")

    def test_valid_candidate_passes(self):
        valid, reason, norm = discovery.should_visit_url("/about-us", base_url="https://site.test/")
        self.assertTrue(valid)
        self.assertEqual(norm, "https://site.test/about-us")
        self.assertEqual(reason, "valid_candidate")


class TestCrawlerPriorityScoring(unittest.TestCase):
    def test_role_priority_boosts(self):
        score_about = discovery.score_url_priority("https://site.test/about", inferred_role="about")
        score_generic = discovery.score_url_priority("https://site.test/page1", inferred_role="general")
        self.assertGreater(score_about, score_generic)

    def test_sitemap_bonus(self):
        score_sitemap = discovery.score_url_priority("https://site.test/p", from_sitemap=True)
        score_normal = discovery.score_url_priority("https://site.test/p", from_sitemap=False)
        self.assertGreater(score_sitemap, score_normal)

    def test_high_value_anchor_bonus(self):
        score_contact = discovery.score_url_priority("https://site.test/c", link_text="Contact Our Team")
        score_plain = discovery.score_url_priority("https://site.test/c", link_text="Click here")
        self.assertGreater(score_contact, score_plain)

    def test_low_value_anchor_penalty(self):
        score_privacy = discovery.score_url_priority("https://site.test/privacy", link_text="Privacy Policy")
        score_product = discovery.score_url_priority("https://site.test/prod", link_text="Our Products")
        self.assertLess(score_privacy, score_product)

    def test_depth_penalty(self):
        score_d1 = discovery.score_url_priority("https://site.test/a", depth=1)
        score_d3 = discovery.score_url_priority("https://site.test/a", depth=3)
        self.assertGreater(score_d1, score_d3)


class TestCrawlerExecutionAndSitemaps(unittest.TestCase):
    def test_sitemap_index_discovery_and_crawl(self):
        robots_txt = "User-agent: *\nAllow: /\nSitemap: https://site.test/sitemap-index.xml"
        sitemap_index_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <sitemap><loc>https://site.test/sitemap-sub.xml</loc></sitemap>
        </sitemapindex>"""
        sitemap_sub_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url><loc>https://site.test/products/alpha</loc></url>
            <url><loc>https://site.test/about</loc></url>
        </urlset>"""

        responses = [
            MockResponse(robots_txt, 200, "https://site.test/robots.txt"),
            MockResponse("<html><body><h1>Home</h1><a href='/contact'>Contact</a></body></html>", 200, "https://site.test/"),
            MockResponse(sitemap_index_xml, 200, "https://site.test/sitemap-index.xml"),
            MockResponse(sitemap_sub_xml, 200, "https://site.test/sitemap-sub.xml"),
            MockResponse("<html><body><h1>About Us</h1><p>Our story</p></body></html>", 200, "https://site.test/about"),
            MockResponse("<html><body><h1>Product Alpha</h1><p>Features</p></body></html>", 200, "https://site.test/products/alpha"),
            MockResponse("<html><body><h1>Contact</h1><p>Email us</p></body></html>", 200, "https://site.test/contact"),
        ]

        with patch.object(run_audit, "_open_url", side_effect=responses):
            report = run_audit.run_pipeline("https://site.test/", enhanced=True, max_pages=10)

        self.assertEqual(report["site"], "site.test")
        self.assertIn("coverage", report)
        self.assertGreaterEqual(report["coverage"]["pages_sampled"], 3)
        sampled_urls = [p["url"] for p in report["evidence_coverage"]["pages_inspected"]]
        self.assertIn("https://site.test/", sampled_urls)

    def test_host_circuit_breaker_trips_gracefully(self):
        robots_txt = "User-agent: *\nAllow: /"
        seed_html = '<html><body><h1>Home</h1><a href="/p1">P1</a><a href="/p2">P2</a><a href="/p3">P3</a><a href="/p4">P4</a></body></html>'

        responses = [
            MockResponse(robots_txt, 200, "https://site.test/robots.txt"),
            MockResponse(seed_html, 200, "https://site.test/"),
            MockResponse("", 404, "https://site.test/sitemap.xml"),
            # 3 consecutive 500 errors to trip circuit breaker
            HTTPError("https://site.test/p1", 500, "Server Error", {}, None),
            HTTPError("https://site.test/p2", 500, "Server Error", {}, None),
            HTTPError("https://site.test/p3", 500, "Server Error", {}, None),
        ]

        with patch.object(run_audit, "_open_url", side_effect=responses):
            report = run_audit.run_pipeline("https://site.test/", enhanced=True, max_pages=10)

        self.assertEqual(report["site"], "site.test")
        self.assertEqual(report["coverage"]["stopping_condition"], "circuit_breaker_tripped")
        self.assertEqual(report["coverage"]["pages_sampled"], 1)  # Only seed succeeded

    def test_soft_block_detection(self):
        captcha_html = "<html><head><title>Access Denied</title></head><body><p>Please verify you are a human captcha security check</p></body></html>"
        is_blocked = run_audit.check_soft_block(captcha_html, 200)
        self.assertTrue(is_blocked)

        normal_html = "<html><head><title>Welcome</title></head><body><h1>Company</h1><p>We build great software.</p></body></html>"
        is_normal_blocked = run_audit.check_soft_block(normal_html, 200)
        self.assertFalse(is_normal_blocked)


class TestContentTypeSemantics(unittest.TestCase):
    """Regression tests for Content-Type classification and HTML absence protection."""

    def test_200_valid_text_html(self):
        resp = MockResponse("<html><body><h1>Title</h1></body></html>", 200, headers={"Content-Type": "text/html; charset=utf-8"})
        with patch.object(run_audit, "_open_url", return_value=resp):
            res = run_audit.fetch_page("https://site.test/page", allow_localhost=True)
        self.assertFalse(res["is_unsupported_content_type"])
        self.assertIn("<h1>Title</h1>", res["raw_html"])

    def test_200_no_content_type_with_html_sniff(self):
        resp = MockResponse("<!DOCTYPE html><html><head><title>Test</title></head><body><h1>Hi</h1></body></html>", 200, headers={})
        with patch.object(run_audit, "_open_url", return_value=resp):
            res = run_audit.fetch_page("https://site.test/page", allow_localhost=True)
        self.assertFalse(res["is_unsupported_content_type"])
        self.assertIn("<h1>Hi</h1>", res["raw_html"])

    def test_200_no_content_type_with_binary_body(self):
        resp = MockResponse("PK\x03\x04\x14\x00\x00\x00\x08\x00some_binary_zip_stream", 200, headers={})
        with patch.object(run_audit, "_open_url", return_value=resp):
            res = run_audit.fetch_page("https://site.test/page", allow_localhost=True)
        self.assertTrue(res["is_unsupported_content_type"])
        self.assertEqual(res["raw_html"], "")

    def test_200_application_pdf(self):
        resp = MockResponse("%PDF-1.7 ...", 200, headers={"Content-Type": "application/pdf"})
        with patch.object(run_audit, "_open_url", return_value=resp):
            res = run_audit.fetch_page("https://site.test/doc.pdf", allow_localhost=True)
        self.assertTrue(res["is_unsupported_content_type"])
        self.assertEqual(res["raw_html"], "")

    def test_200_image_jpeg(self):
        resp = MockResponse("\xff\xd8\xff\xe0\x00\x10JFIF", 200, headers={"Content-Type": "image/jpeg"})
        with patch.object(run_audit, "_open_url", return_value=resp):
            res = run_audit.fetch_page("https://site.test/photo.jpg", allow_localhost=True)
        self.assertTrue(res["is_unsupported_content_type"])
        self.assertEqual(res["raw_html"], "")

    def test_200_binary_octet_stream(self):
        resp = MockResponse("\x00\x01\x02\x03\x04", 200, headers={"Content-Type": "application/octet-stream"})
        with patch.object(run_audit, "_open_url", return_value=resp):
            res = run_audit.fetch_page("https://site.test/data.bin", allow_localhost=True)
        self.assertTrue(res["is_unsupported_content_type"])
        self.assertEqual(res["raw_html"], "")

    def test_unsupported_content_type_emits_no_html_absence_findings(self):
        """A 200 OK binary or PDF response must not emit missing H1, missing CTA, or thin content findings."""
        pdf_resp = MockResponse("%PDF-1.7 binary content...", 200, headers={"Content-Type": "application/pdf"})
        robots_resp = MockResponse("User-agent: *\nAllow: /\n", 200, headers={"Content-Type": "text/plain"})

        def mock_open(req, timeout=10):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            if url.endswith("robots.txt"):
                return robots_resp
            return pdf_resp

        with patch.object(run_audit, "_open_url", side_effect=mock_open):
            report = run_audit.run_pipeline("https://site.test/manual.pdf", enhanced=True, max_pages=3)

        emitted_rule_ids = [f.get("rule_id") for f in report["findings"]]
        forbidden_rules = {"ENG-H1-ZERO-001", "ENG-CTA-MISSING-001", "CQ-THIN-001", "SD-MISSING-001"}
        self.assertEqual(set(emitted_rule_ids) & forbidden_rules, set(),
                         f"Unsupported content type emitted false absence findings: {emitted_rule_ids}")


if __name__ == "__main__":
    unittest.main()
