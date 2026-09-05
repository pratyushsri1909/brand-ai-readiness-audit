import ast
import glob
import importlib.util
import os
import time
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
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parents[1]

SPEC_ORCH = importlib.util.spec_from_file_location("run_audit", ROOT / "skills/audit-orchestrator/scripts/run_audit.py")
run_audit = importlib.util.module_from_spec(SPEC_ORCH)
SPEC_ORCH.loader.exec_module(run_audit)

SPEC_CQ = importlib.util.spec_from_file_location("content_quality", ROOT / "skills/content-quality-audit/scripts/detector.py")
content_quality = importlib.util.module_from_spec(SPEC_CQ)
SPEC_CQ.loader.exec_module(content_quality)

SPEC_RULES = importlib.util.spec_from_file_location("rules", ROOT / "skills/audit-orchestrator/scripts/rules.py")
rules = importlib.util.module_from_spec(SPEC_RULES)
SPEC_RULES.loader.exec_module(rules)


class MockResponse:
    def __init__(self, text="", status=200, url="https://site.test/page", headers=None):
        self.text = text
        self.status = status
        self.url = url
        self.headers = headers or {}

    def read(self, n=-1):
        return self.text.encode("utf-8")

    def getcode(self):
        return self.status

    def geturl(self):
        return self.url

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class TestGlobalRuntimeBudget(unittest.TestCase):
    """P0-1: Global Hard Runtime Budget tests."""

    def test_immediate_deadline_exhaustion(self):
        """When deadline is already in the past, crawl loop stops immediately with runtime_budget_exhausted."""
        now = [100.0]
        def fake_monotonic():
            t = now[0]
            now[0] += 0.05
            return t

        def mock_open(req, timeout=10):
            return MockResponse("<html><body><h1>Hello</h1><a href='/s1'>S1</a></body></html>", 200, req.full_url)

        with patch.object(run_audit.time, "monotonic", side_effect=fake_monotonic):
            with patch.object(run_audit, "_open_url", side_effect=mock_open):
                report = run_audit.run_pipeline("https://site.test/", enhanced=True, max_pages=10, global_timeout=0.01)

        cov = report["coverage"]
        self.assertIn("runtime_budget_seconds", cov)
        self.assertIn("runtime_elapsed_seconds", cov)
        self.assertTrue(cov["runtime_budget_exhausted"])
        self.assertIn(cov["crawl_stop_reason"], ("runtime_budget_exhausted", "page_budget_exhausted"))

    def test_deadline_prevents_additional_fetches(self):
        """Network fetches stop as soon as deadline expires."""
        current_time = [1000.0]

        def fake_monotonic():
            t = current_time[0]
            current_time[0] += 10.0  # Increment 10s per step
            return t

        def mock_open(req, timeout=10):
            url = req.full_url
            if url.endswith("/robots.txt"):
                return MockResponse("User-agent: *\nAllow: /\n", 200, url)
            return MockResponse("<html><body><h1>Hello</h1><a href='/sub1'>Sub1</a><a href='/sub2'>Sub2</a></body></html>", 200, url)

        with patch.object(run_audit.time, "monotonic", side_effect=fake_monotonic):
            with patch.object(run_audit, "_open_url", side_effect=mock_open):
                report = run_audit.run_pipeline("https://site.test/", enhanced=True, max_pages=10, global_timeout=120.0)

        self.assertTrue(report["coverage"]["runtime_budget_exhausted"], f"Expected runtime_budget_exhausted True, got {report.get('coverage')}")
        self.assertEqual(report["coverage"]["crawl_stop_reason"], "runtime_budget_exhausted")


class TestBoundedSitemapTraversal(unittest.TestCase):
    """P0-2: Complete Bounded Sitemap Index Traversal tests."""

    def test_sitemap_index_and_nested_index_traversal(self):
        """Orchestrator resolves sitemap indexes and child sitemaps up to limits."""
        sitemap_index_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <sitemap><loc>https://site.test/sitemap-child-1.xml</loc></sitemap>
            <sitemap><loc>https://site.test/sitemap-child-2.xml</loc></sitemap>
        </sitemapindex>"""

        child_1_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url><loc>https://site.test/page-a</loc></url>
            <url><loc>https://site.test/page-b</loc></url>
        </urlset>"""

        child_2_xml = """<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url><loc>https://site.test/page-c</loc></url>
        </urlset>"""

        responses = [
            MockResponse(sitemap_index_xml, 200, "https://site.test/sitemap.xml"),
            MockResponse(child_1_xml, 200, "https://site.test/sitemap-child-1.xml"),
            MockResponse(child_2_xml, 200, "https://site.test/sitemap-child-2.xml"),
        ]

        with patch.object(run_audit, "_open_url", side_effect=responses):
            urls, sample, meta = run_audit.fetch_sitemap_tree(
                "https://site.test/", "", {"status": "ok", "content": "User-agent: *\nAllow: /\n"}
            )

        self.assertEqual(len(urls), 3)
        self.assertIn("https://site.test/page-a", urls)
        self.assertIn("https://site.test/page-b", urls)
        self.assertIn("https://site.test/page-c", urls)
        self.assertEqual(meta["sitemaps_fetched"], 3)
        self.assertFalse(meta["limit_reached"])

    def test_sitemap_cycle_prevention(self):
        """Cyclic sitemap references do not cause infinite recursion."""
        cycle_xml_a = """<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <sitemap><loc>https://site.test/sitemap-b.xml</loc></sitemap>
        </sitemapindex>"""
        cycle_xml_b = """<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <sitemap><loc>https://site.test/sitemap.xml</loc></sitemap>
        </sitemapindex>"""

        responses = [
            MockResponse(cycle_xml_a, 200, "https://site.test/sitemap.xml"),
            MockResponse(cycle_xml_b, 200, "https://site.test/sitemap-b.xml"),
        ]

        with patch.object(run_audit, "_open_url", side_effect=responses):
            urls, sample, meta = run_audit.fetch_sitemap_tree(
                "https://site.test/", "", {"status": "ok", "content": "User-agent: *\nAllow: /\n"}
            )

        self.assertEqual(meta["sitemaps_fetched"], 2)


class TestCrossOriginRobotsPolicy(unittest.TestCase):
    """P0-3: Robots Policy for Destination Origins and Redirects."""

    def test_cross_origin_sitemap_destination_robots(self):
        """Cross-origin sitemap URL origin robots.txt is queried and cached."""
        robots_cache = run_audit.RobotsCache()

        # Destination origin disallows crawling
        parsed_other = run_audit.urlparse("https://cdn.other.test/sitemap.xml")
        with patch.object(run_audit, "_open_url", return_value=MockResponse("User-agent: *\nDisallow: /", 200, "https://cdn.other.test/robots.txt")):
            res = robots_cache.get_robots(parsed_other)

        self.assertEqual(res["status"], "ok")
        self.assertFalse(robots_cache.allows("https://cdn.other.test/sitemap.xml", robots_result=res))

        # Re-querying uses cache without re-fetching
        with patch.object(run_audit, "_open_url", side_effect=AssertionError("Should not re-fetch cached origin")):
            cached_res = robots_cache.get_robots(parsed_other)
            self.assertEqual(cached_res["status"], "ok")


class TestRedirectScopeAndFinalUrl(unittest.TestCase):
    """P0-4: Redirect Scope and Final URL Safety."""

    def test_external_redirect_is_skipped_and_not_enqueued(self):
        """A subpage redirecting to an external site is recorded in pages_skipped and not crawled."""
        responses = [
            MockResponse("User-agent: *\nAllow: /\n", 200, "https://site.test/robots.txt"),
            MockResponse("<html><body><a href='/out'>Out Link</a></body></html>", 200, "https://site.test/"),
            MockResponse("", 404, "https://site.test/sitemap.xml"),
            # /out redirects externally to https://external.com/
            MockResponse("", 302, "https://site.test/out", {"Location": "https://external.com/"}),
            MockResponse("User-agent: *\nAllow: /\n", 200, "https://external.com/robots.txt"),
            MockResponse("<html><body><h1>External Page</h1></body></html>", 200, "https://external.com/"),
        ]

        with patch.object(run_audit, "_open_url", side_effect=responses):
            report = run_audit.run_pipeline("https://site.test/", enhanced=True, max_pages=10)

        # External page must NOT be in pages_inspected
        inspected_urls = [p["url"] for p in report["evidence_coverage"]["pages_inspected"]]
        self.assertNotIn("https://external.com/", inspected_urls)

        # External redirect must be recorded in pages_skipped
        skipped_reasons = [p.get("reason") for p in report["evidence_coverage"]["pages_skipped"]]
        self.assertIn("external_redirect_out_of_scope", skipped_reasons)


class TestBrowserEscalationFallback(unittest.TestCase):
    """P0-5: HTTP-first -> Browser Fallback Escalation."""

    def test_escalation_triggers_on_spa_mount_with_low_text(self):
        """Page with empty SPA container and low visible text triggers browser escalation."""
        profile = {
            "html": "<html><head><script src='app.js'></script></head><body><div id='root'></div></body></html>",
        }
        escalate, reason = run_audit.should_escalate_to_browser(profile)
        self.assertTrue(escalate)
        self.assertEqual(reason, "empty_root_low_static_text")

    def test_no_escalation_on_content_rich_static_html(self):
        """Page with rich static copy does not trigger browser escalation."""
        profile = {
            "html": "<html><body><h1>Title</h1><p>" + ("Substantive text content. " * 50) + "</p></body></html>",
        }
        escalate, reason = run_audit.should_escalate_to_browser(profile)
        self.assertFalse(escalate)
        self.assertEqual(reason, "static_content_sufficient")

    def test_playwright_unavailable_graceful_fallback(self):
        """When Playwright is not available, returns graceful fallback metadata."""
        with patch.dict("sys.modules", {"playwright.sync_api": None}):
            content, available, fallback_reason = run_audit.render_with_browser("https://site.test/")
            self.assertIsNone(content)
            self.assertFalse(available)
            self.assertIn("playwright", fallback_reason)


class TestMainContentExtraction(unittest.TestCase):
    """P0-6: Main Content Extraction for Duplicate Detection."""

    def test_boilerplate_ignored_different_main_content(self):
        """Pages with identical header/nav/footer but different <main> are NOT flagged as duplicates."""
        html_page_1 = """<!DOCTYPE html>
        <html>
        <head><title>Page 1</title></head>
        <body>
            <header><nav><a href='/'>Home</a><a href='/products'>Products</a><a href='/about'>About</a></nav></header>
            <div id='cookie-banner'>We use cookies to personalize your experience. Accept All.</div>
            <main>
                <h1>Autonomous AI Systems</h1>
                <p>Detailed technical documentation regarding agent memory, execution sandboxing, and deterministic orchestration.</p>
            </main>
            <footer><p>Copyright 2026 Acme Corp. All rights reserved. Privacy policy. Terms of service.</p></footer>
        </body>
        </html>"""

        html_page_2 = """<!DOCTYPE html>
        <html>
        <head><title>Page 2</title></head>
        <body>
            <header><nav><a href='/'>Home</a><a href='/products'>Products</a><a href='/about'>About</a></nav></header>
            <div id='cookie-banner'>We use cookies to personalize your experience. Accept All.</div>
            <main>
                <h1>Quantum Computing Fundamentals</h1>
                <p>An introduction to quantum annealing, superconducting qubits, error mitigation, and quantum circuit synthesis.</p>
            </main>
            <footer><p>Copyright 2026 Acme Corp. All rights reserved. Privacy policy. Terms of service.</p></footer>
        </body>
        </html>"""

        text_1, meta_1 = content_quality.extract_main_content_text(html_page_1)
        text_2, meta_2 = content_quality.extract_main_content_text(html_page_2)

        self.assertIn("Autonomous AI Systems", text_1)
        self.assertNotIn("Copyright 2026", text_1)
        self.assertNotIn("We use cookies", text_1)

        self.assertIn("Quantum Computing Fundamentals", text_2)
        self.assertNotIn("Copyright 2026", text_2)

        # Audit both pages together
        artifacts = [
            {"url": "https://site.test/p1", "html": html_page_1},
            {"url": "https://site.test/p2", "html": html_page_2},
        ]
        res = content_quality.audit({"page_artifacts": artifacts})
        dup_findings = [f for f in res.get("findings", []) if "Duplicate" in f["title"]]
        self.assertEqual(len(dup_findings), 0)

    def test_same_main_content_flagged_as_duplicate(self):
        """Pages with identical substantive main content are detected as exact duplicates."""
        html_page_1 = """<html><body><nav>Nav A</nav><main><h1>Identical Article</h1><p>Unique core body content.</p></main><footer>Footer A</footer></body></html>"""
        html_page_2 = """<html><body><nav>Nav B</nav><main><h1>Identical Article</h1><p>Unique core body content.</p></main><footer>Footer B</footer></body></html>"""

        artifacts = [
            {"url": "https://site.test/art1", "html": html_page_1},
            {"url": "https://site.test/art2", "html": html_page_2},
        ]
        res = content_quality.audit({"page_artifacts": artifacts})
        dup_findings = [f for f in res.get("findings", []) if "Duplicate" in f["title"]]
        self.assertGreaterEqual(len(dup_findings), 1)


class TestNoFabricatedValuesRepoWide(unittest.TestCase):
    """P0-7: Repository-wide check ensuring recommendation snippets contain zero fabricated values."""

    def test_no_fabricated_literals_in_rule_snippets(self):
        """Scans all generated snippet templates for banned fabricated values (USD, 99.00, fake dates)."""
        banned_literals = ["99.00", "2026-01-01", "2026-09-01"]
        context = {"host": "example.com", "url": "https://example.com"}

        for rule_id, rule_def in rules.RULE_REGISTRY.items():
            if rule_def.get("snippet_eligible") and rule_def.get("snippet_type"):
                snippet = rules.generate_safe_snippet(rule_id, rule_def["snippet_type"], context)
                if snippet and "code" in snippet:
                    code = snippet["code"]
                    for banned in banned_literals:
                        self.assertNotIn(
                            banned, code,
                            f"Rule {rule_id} contains fabricated literal '{banned}' in recommended snippet!"
                        )


class TestNoUnsupportedClaimsRepoWide(unittest.TestCase):
    """P0-8: Toned down FAQ / AI guarantee claims check."""

    def test_no_guarantee_wording_in_rules_or_expected_mechanisms(self):
        """Scans rules for unsupported guarantee assertions."""
        banned_phrases = [
            "guarantees ranking", "guarantee ranking",
            "guarantees inclusion", "guarantee inclusion",
            "guarantees ai citation", "guarantee ai citation",
            "guarantees discovery", "guarantee discovery",
        ]

        for rule_id, rule_def in rules.RULE_REGISTRY.items():
            mechanism = rule_def.get("expected_mechanism", "").lower()
            root_cause = rule_def.get("root_cause", "").lower()
            for banned in banned_phrases:
                self.assertNotIn(banned, mechanism, f"Rule {rule_id} contains unsupported guarantee phrase '{banned}'")
                self.assertNotIn(banned, root_cause, f"Rule {rule_id} contains unsupported guarantee phrase '{banned}'")


class TestBoundedRetries(unittest.TestCase):
    """P1-9: Bounded Retries on transient failures."""

    def test_retry_on_500_with_max_retries(self):
        """Transient 500 error retries up to max_retries."""
        responses = [
            HTTPError("https://site.test/p", 500, "Server Error", {}, None),
            MockResponse("<html><body><h1>Recovered</h1></body></html>", 200, "https://site.test/p"),
        ]
        with patch.object(run_audit, "_open_url", side_effect=responses):
            res = run_audit.fetch_page("https://site.test/p", max_retries=1)

        self.assertEqual(res["status_code"], 200)
        self.assertEqual(res["retries"], 1)

    def test_no_retry_on_404(self):
        """Permanent 404 is never retried."""
        responses = [
            HTTPError("https://site.test/p", 404, "Not Found", {}, None),
            MockResponse("<html><body><h1>Never Called</h1></body></html>", 200, "https://site.test/p"),
        ]
        with patch.object(run_audit, "_open_url", side_effect=responses) as mocked:
            res = run_audit.fetch_page("https://site.test/p", max_retries=2)

        self.assertEqual(res["status_code"], 404)
        self.assertEqual(res["retries"], 0)
        self.assertEqual(len(mocked.call_args_list), 1)


class TestReadOnlySafety(unittest.TestCase):
    """Safety Constraint: Read-only auditing with no POST/PUT/DELETE or mutations."""

    def test_no_http_mutation_methods_in_production_code(self):
        """Scans all production python scripts to ensure no POST/PUT/DELETE requests exist."""
        script_files = glob.glob(str(ROOT / "skills/**/*.py"), recursive=True)
        mutation_verbs = {"method='POST'", 'method="POST"', "method='PUT'", 'method="PUT"', "method='DELETE'", 'method="DELETE"'}

        for filepath in script_files:
            if "tests" in filepath or "test_" in filepath:
                continue
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
                for verb in mutation_verbs:
                    self.assertNotIn(verb, content, f"Mutation HTTP verb {verb} found in production file: {filepath}")


class TestRedirectScopeHardening(unittest.TestCase):
    """P0-3: Out-of-scope redirect destination protection."""

    def test_same_origin_redirect_followed(self):
        class RedirectResp:
            def __init__(self, target): self.headers = {"Location": target}
            def getcode(self): return 301
            def geturl(self): return "https://site.test/old"
            def __enter__(self): return self
            def __exit__(self, *a): return False

        responses = [
            RedirectResp("https://site.test/new"),
            MockResponse("<html><body><h1>New Page</h1></body></html>", 200, "https://site.test/new"),
        ]
        initial_robots = {"status": "ok", "content": "User-agent: *\nAllow: /\n", "url": "https://site.test/robots.txt"}
        with patch.object(run_audit, "_open_url", side_effect=responses):
            res = run_audit.fetch_page("https://site.test/old", initial_robots=initial_robots, target_host="site.test")

        self.assertEqual(res["status_code"], 200)
        self.assertEqual(res["final_url"], "https://site.test/new")
        self.assertEqual(res["redirect_chain"], ["https://site.test/old"])

    def test_external_redirect_body_not_fetched(self):
        class ExtRedirectResp:
            def __init__(self, target): self.headers = {"Location": target}
            def getcode(self): return 302
            def geturl(self): return "https://site.test/partner"
            def __enter__(self): return self
            def __exit__(self, *a): return False

        responses = [
            ExtRedirectResp("https://external-partner.test/landing"),
        ]
        with patch.object(run_audit, "_open_url", side_effect=responses) as mocked:
            res = run_audit.fetch_page("https://site.test/partner", target_host="site.test")

        self.assertEqual(res["error"], "external_redirect_out_of_scope")
        self.assertEqual(res["raw_html"], "")
        self.assertEqual(res["final_url"], "https://external-partner.test/landing")
        self.assertEqual(res["redirect_scope"], "external")
        # Assert external URL was never requested
        self.assertEqual(len(mocked.call_args_list), 1)

    def test_redirect_chain_ending_externally_stops_before_external_fetch(self):
        class Hop1Resp:
            def __init__(self): self.headers = {"Location": "https://site.test/hop2"}
            def getcode(self): return 301
            def geturl(self): return "https://site.test/hop1"
            def __enter__(self): return self
            def __exit__(self, *a): return False

        class Hop2Resp:
            def __init__(self): self.headers = {"Location": "https://other-site.test/final"}
            def getcode(self): return 302
            def geturl(self): return "https://site.test/hop2"
            def __enter__(self): return self
            def __exit__(self, *a): return False

        initial_robots = {"status": "ok", "content": "User-agent: *\nAllow: /\n", "url": "https://site.test/robots.txt"}
        with patch.object(run_audit, "_open_url", side_effect=[Hop1Resp(), Hop2Resp()]) as mocked:
            res = run_audit.fetch_page("https://site.test/hop1", initial_robots=initial_robots, target_host="site.test")

        self.assertEqual(res["error"], "external_redirect_out_of_scope")
        self.assertEqual(res["final_url"], "https://other-site.test/final")
        self.assertEqual(res["redirect_chain"], ["https://site.test/hop1", "https://site.test/hop2"])
        self.assertEqual(len(mocked.call_args_list), 2)


class TestCentralizedBrowserSafety(unittest.TestCase):
    """P0-4: Centralized Safety Policy for Playwright navigation."""

    def test_browser_rejects_localhost_by_default(self):
        html, avail, reason = run_audit.render_with_browser("http://localhost:8080/app")
        self.assertIsNone(html)
        self.assertFalse(avail)
        self.assertIn("browser_safety_rejected", reason)

    def test_browser_rejects_private_ip(self):
        html, avail, reason = run_audit.render_with_browser("http://192.168.1.1/router")
        self.assertIsNone(html)
        self.assertFalse(avail)
        self.assertIn("browser_safety_rejected", reason)

    def test_browser_rejects_external_target(self):
        html, avail, reason = run_audit.render_with_browser("https://external-domain.com/page", target_host="site.test")
        self.assertIsNone(html)
        self.assertFalse(avail)
        self.assertIn("out_of_scope", reason)

    def test_browser_rejects_expired_deadline(self):
        html, avail, reason = run_audit.render_with_browser("https://site.test/page", target_host="site.test", deadline=time.monotonic() - 10)
        self.assertIsNone(html)
        self.assertFalse(avail)
        self.assertIn("runtime_budget_exhausted", reason)


class TestSitemapStreamingReadLimit(unittest.TestCase):
    """P1-6: Enforce response size limits during network read."""

    def test_sitemap_read_limited_to_max_sitemap_bytes(self):
        class LargeMockResponse:
            def __init__(self):
                self.bytes_read = 0
            def read(self, max_bytes=None):
                self.bytes_read = max_bytes
                return b"<urlset></urlset>"
            def getcode(self): return 200
            def geturl(self): return "https://site.test/sitemap.xml"
            def __enter__(self): return self
            def __exit__(self, *a): return False
            headers = {}

        resp = LargeMockResponse()
        with patch.object(run_audit, "_open_url", return_value=resp):
            res = run_audit.fetch_page("https://site.test/sitemap.xml", max_response_bytes=run_audit.MAX_SITEMAP_RESPONSE_BYTES)

        self.assertEqual(resp.bytes_read, run_audit.MAX_SITEMAP_RESPONSE_BYTES)


class TestSoftBlockSuppression(unittest.TestCase):
    """P1-9: Soft-block / challenge pages do not create misleading thin content findings."""

    def test_soft_block_suppresses_thin_content(self):
        cf_challenge_html = """<!DOCTYPE html>
        <html>
        <head><title>Just a moment...</title></head>
        <body class="cf-challenge-running">
            <h1>Checking your browser before accessing</h1>
            <p>Please verify you are a human. DDoS protection by Cloudflare.</p>
        </body>
        </html>"""

        profile = {
            "url": "https://site.test/challenge",
            "html": cf_challenge_html,
            "status_code": 200,
            "page_role": "article",
            "is_soft_blocked": True,
        }

        detector = run_audit.content_quality_detector
        res = detector.audit(profile)
        findings = res.get("findings", [])
        titles = [f["title"] for f in findings]

        self.assertNotIn("Thin Content Detected", titles)
        self.assertIn("Page Content Unverifiable (Soft-Block/Challenge Detected)", titles)


class TestPhase1RenderConfidence(unittest.TestCase):
    """Phase 1: extraction failure must not cascade into absence findings."""

    def test_escalation_triggered_for_script_heavy_low_text_page(self):
        html = "<html><body><div id=\"app\"></div>" + ("<script>var x=1;</script>" * 6) + "</body></html>"
        profile = {"html": html, "status_code": 200, "fetch_mode": "http_static"}
        escalate, reason = run_audit.should_escalate_to_browser(profile)
        self.assertTrue(escalate)
        self.assertTrue(reason)

    def test_uncertain_extraction_suppresses_content_absence_cascade(self):
        html = "<html><head><title>Loading</title></head><body><div id=\"root\"></div></body></html>"
        profile = {
            "url": "https://spa.test/", "html": html, "status_code": 200,
            "fetch_mode": "http_static", "page_role": "homepage",
            "extraction_uncertain": True, "is_soft_blocked": False,
        }
        findings = run_audit.content_quality_detector.audit(profile)["findings"]
        self.assertEqual(findings, [])

class TestRenderedContentPipeline(unittest.TestCase):
    """P1-10: Rendered content is used when browser escalation occurs."""

    def test_rendered_content_used_in_analysis(self):
        static_empty_shell = """<!DOCTYPE html>
        <html>
        <head><title>SPA App</title></head>
        <body>
            <div id="root"></div>
            <script src="/app.js"></script>
        </body>
        </html>"""

        rendered_full_html = """<!DOCTYPE html>
        <html>
        <head><title>SPA App - Rendered</title></head>
        <body>
            <div id="root">
                <main>
                    <h1>Hydrated Dashboard</h1>
                    <p>Substantive client-rendered content loaded dynamically after hydration.</p>
                </main>
            </div>
        </body>
        </html>"""

        profile = {
            "url": "https://site.test/spa",
            "requested_url": "https://site.test/spa",
            "final_url": "https://site.test/spa",
            "raw_html": static_empty_shell,
            "status_code": 200,
            "headers": {},
        }
        built = run_audit.build_page_profile("https://site.test/spa", profile, "2026-01-01T00:00:00Z")
        self.assertEqual(built["analysis_source"], "static")

        # Simulate browser escalation
        built["rendered_html"] = rendered_full_html
        built["html"] = rendered_full_html
        built["analysis_html"] = rendered_full_html
        built["analysis_source"] = "rendered"

        cq_res = run_audit.content_quality_detector.audit(built)
        text = run_audit.crawl_detector.readable_text(built["html"])
        self.assertIn("Hydrated Dashboard", text)


class TestPhase1PageRolePropagation(unittest.TestCase):
    def test_specific_upstream_role_is_preserved_when_url_classifier_is_general(self):
        fetch_result = {
            "final_url": "https://site.test/catalog/item-123",
            "raw_html": "<html><body><h1>Item 123</h1><p>Product details and specifications.</p></body></html>",
            "status_code": 200, "headers": {}, "content_type": "text/html",
        }
        profile = run_audit.build_page_profile(
            "https://site.test/catalog/item-123", fetch_result, "2026-01-01T00:00:00Z",
            role_hint="product"
        )
        self.assertEqual(profile["page_role"], "product")
        self.assertEqual(profile["page_intent"], "product")


class TestNestedBoilerplateMainContent(unittest.TestCase):
    """P1-11: Harden main content extraction against nested excluded regions."""

    def test_main_nested_inside_header_ignored_in_favor_of_article(self):
        html = """<!DOCTYPE html>
        <html>
        <body>
            <header>
                <main>Header Navigation Menu</main>
            </header>
            <article>
                <h1>Real Main Article Heading</h1>
                <p>This is the actual substantive content of the article page.</p>
            </article>
            <footer>Footer Links</footer>
        </body>
        </html>"""
        detector = run_audit.content_quality_detector
        text, meta = detector.extract_main_content_text(html)
        self.assertEqual(meta["content_source"], "article")
        self.assertIn("Real Main Article Heading", text)
        self.assertNotIn("Header Navigation Menu", text)

    def test_main_nested_inside_cookie_banner_ignored(self):
        html = """<!DOCTYPE html>
        <html>
        <body>
            <div class="cookie-banner-modal">
                <main>Accept all cookies banner content</main>
            </div>
            <div class="body-content">
                <h1>Legitimate Content Heading</h1>
                <p>Real article content that must be extracted properly.</p>
            </div>
        </body>
        </html>"""
        detector = run_audit.content_quality_detector
        text, meta = detector.extract_main_content_text(html)
        self.assertIn("Legitimate Content Heading", text)
        self.assertNotIn("Accept all cookies", text)


if __name__ == "__main__":
    unittest.main()
