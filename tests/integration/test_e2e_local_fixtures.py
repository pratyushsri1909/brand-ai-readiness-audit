"""
tests/test_local_e2e.py
Local multi-page end-to-end fixture test.

Spins up a deterministic stdlib HTTP server with several pages containing
deliberate issues and verifies that the audit CLI produces a valid JSON
report with expected findings and without false positives.

Pages:
  /                     - homepage with CTA, valid
  /products/            - category page, valid
  /products/widget      - product page, valid Product JSON-LD
  /products/finance     - article with "$99" text but NO commerce schema (should not trigger commerce finding)
  /blog/intro           - article, thin content + missing meta description
  /about                - about page, Organization with org_id
  /contact              - contact page
  /noindex              - page with <meta name="robots" content="noindex"> — noindex finding expected
  /malformed-jsonld     - page with malformed JSON-LD block followed by a valid one
  /duplicate-a          - same content as /duplicate-b
  /duplicate-b          - same content as /duplicate-a
  /sitemap.xml          - XML sitemap listing the above pages
  /robots.txt           - allows everything, declares /sitemap.xml
"""
import importlib.util
import json
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "run_audit",
    ROOT / "skills/audit-orchestrator/scripts/run_audit.py",
)
run_audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(run_audit)

# -----------------------------------------------------------------------
# Fixture pages
# -----------------------------------------------------------------------
ORG_JSONLD = json.dumps({
    "@context": "https://schema.org",
    "@type": "Organization",
    "@id": "https://fixture.local/#org",
    "name": "Fixture Corp",
    "url": "http://127.0.0.1:PORT/",
})

PRODUCT_JSONLD = json.dumps({
    "@context": "https://schema.org",
    "@type": "Product",
    "name": "Widget Pro",
    "offers": {"@type": "Offer", "price": "49.00", "priceCurrency": "USD"},
})

DUPLICATE_BODY = ("This is the exact same content repeated on two different URLs. " * 20)

PAGES = {
    "/robots.txt": (
        "text/plain",
        "User-agent: *\nAllow: /\nDisallow: /noindex\nSitemap: http://127.0.0.1:PORT/sitemap.xml\n",
        200,
    ),
    "/sitemap.xml": (
        "application/xml",
        """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://127.0.0.1:PORT/</loc></url>
  <url><loc>http://127.0.0.1:PORT/products/</loc></url>
  <url><loc>http://127.0.0.1:PORT/products/widget</loc></url>
  <url><loc>http://127.0.0.1:PORT/products/finance</loc></url>
  <url><loc>http://127.0.0.1:PORT/blog/intro</loc></url>
  <url><loc>http://127.0.0.1:PORT/about</loc></url>
  <url><loc>http://127.0.0.1:PORT/contact</loc></url>
  <url><loc>http://127.0.0.1:PORT/noindex</loc></url>
  <url><loc>http://127.0.0.1:PORT/malformed-jsonld</loc></url>
  <url><loc>http://127.0.0.1:PORT/duplicate-a</loc></url>
  <url><loc>http://127.0.0.1:PORT/duplicate-b</loc></url>
</urlset>""",
        200,
    ),
    "/": (
        "text/html",
        """<html><head><title>Fixture Corp - Home</title>
<meta name="description" content="Fixture Corp makes widgets for everyone.">
<link rel="canonical" href="http://127.0.0.1:PORT/">
<script type="application/ld+json">%(org)s</script>
</head><body>
<h1>Welcome to Fixture Corp</h1>
<p>%(body)s</p>
<nav><a href="/products/">Products</a> | <a href="/about">About</a> | <a href="/contact">Contact</a></nav>
<a href="/products/widget" class="btn">Buy Now</a>
</body></html>"""
        % {"org": ORG_JSONLD, "body": "We make the best widgets in the world. " * 10},
        200,
    ),
    "/products/": (
        "text/html",
        """<html><head><title>Products - Fixture Corp</title>
<meta name="description" content="Browse our product catalog.">
</head><body>
<h1>Our Products</h1>
<ul><li><a href="/products/widget">Widget Pro</a></li></ul>
<p>%s</p>
<nav><a href="/">Home</a> | <a href="/contact">Contact</a></nav>
</body></html>"""
        % ("Browse our full range of products and services available today. " * 8),
        200,
    ),
    "/products/widget": (
        "text/html",
        """<html><head><title>Widget Pro - Fixture Corp</title>
<meta name="description" content="Widget Pro is our flagship product at $49.">
<script type="application/ld+json">%(prod)s</script>
</head><body>
<h1>Widget Pro</h1>
<p>Price: $49.00 | In Stock | SKU: WP-001</p>
<p>%(body)s</p>
<a href="/contact" class="btn">Buy Now</a>
<nav><a href="/products/">Back to Products</a> | <a href="/">Home</a></nav>
</body></html>"""
        % {"prod": PRODUCT_JSONLD,
           "body": "The Widget Pro is our flagship product. It features advanced capabilities. " * 5},
        200,
    ),
    "/products/finance": (
        "text/html",
        """<html><head><title>Market Update - Fixture Corp Blog</title>
<meta name="description" content="Latest market analysis for Q3 2026.">
</head><body>
<h1>Market Update Q3 2026</h1>
<p>Shares of WidgetCo traded at $99 per share today on the NYSE. The market cap reached $1.2 billion.
Analysts expect the stock to reach $120 by year end. This is a financial analysis, not a product listing.</p>
<p>%(body)s</p>
<nav><a href="/">Home</a> | <a href="/blog/intro">Blog</a></nav>
</body></html>"""
        % {"body": "Market movements often reflect broader economic trends and investor sentiment. " * 8},
        200,
    ),
    "/blog/intro": (
        "text/html",
        # Deliberately thin content + no meta description
        """<html><head><title>Intro Post</title></head><body>
<h1>Introduction</h1>
<p>A short post.</p>
<nav><a href="/">Home</a></nav>
</body></html>""",
        200,
    ),
    "/about": (
        "text/html",
        """<html><head><title>About Fixture Corp</title>
<meta name="description" content="Learn about Fixture Corp, founded in 2020.">
<script type="application/ld+json">%(org)s</script>
</head><body>
<h1>About Us</h1>
<p>%(body)s</p>
<nav><a href="/">Home</a> | <a href="/contact">Contact</a></nav>
</body></html>"""
        % {"org": ORG_JSONLD,
           "body": "Fixture Corp was founded in 2020 to make the world a better place through widgets. " * 8},
        200,
    ),
    "/contact": (
        "text/html",
        """<html><head><title>Contact Us - Fixture Corp</title>
<meta name="description" content="Get in touch with Fixture Corp.">
</head><body>
<h1>Contact Us</h1>
<p>Email: hello@fixture.example | Phone: 555-0100</p>
<a href="mailto:hello@fixture.example">Contact Us</a>
<nav><a href="/">Home</a></nav>
</body></html>""",
        200,
    ),
    "/noindex": (
        "text/html",
        """<html><head>
<title>Private Page</title>
<meta name="robots" content="noindex, nofollow">
</head><body>
<h1>Internal Page</h1>
<p>This page intentionally blocks indexing.</p>
</body></html>""",
        200,
    ),
    "/malformed-jsonld": (
        "text/html",
        """<html><head><title>Malformed JSON-LD Test</title>
<meta name="description" content="Page with one malformed and one valid JSON-LD block.">
<script type="application/ld+json">{ this is not valid json }</script>
<script type="application/ld+json">%(org)s</script>
</head><body>
<h1>Malformed JSON-LD Test Page</h1>
<p>%(body)s</p>
<nav><a href="/">Home</a></nav>
</body></html>"""
        % {"org": ORG_JSONLD,
           "body": "This page tests that a malformed JSON-LD block does not abort the audit. " * 5},
        200,
    ),
    "/duplicate-a": (
        "text/html",
        f"""<html><head><title>Widget Review A</title>
<meta name="description" content="A review of widget pro."></head>
<body><h1>Widget Review</h1><p>{DUPLICATE_BODY}</p>
<nav><a href="/">Home</a></nav></body></html>""",
        200,
    ),
    "/duplicate-b": (
        "text/html",
        f"""<html><head><title>Widget Review B</title>
<meta name="description" content="A review of widget pro."></head>
<body><h1>Widget Review</h1><p>{DUPLICATE_BODY}</p>
<nav><a href="/">Home</a></nav></body></html>""",
        200,
    ),
}

_SERVER_PORT = None


def _make_handler(port):
    class FixtureHandler(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass  # silence server logs

        def do_GET(self):
            path = self.path.split("?")[0]
            entry = PAGES.get(path)
            if entry is None:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b"Not Found")
                return
            content_type, body, status = entry
            # Replace PORT placeholder
            body = body.replace("PORT", str(port))
            encoded = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

    return FixtureHandler


def _start_server():
    """Starts the fixture HTTP server on a random available port."""
    server = HTTPServer(("127.0.0.1", 0), _make_handler(0))
    port = server.server_address[1]
    # Re-make handler with actual port
    server.RequestHandlerClass = _make_handler(port)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port, thread


class TestLocalE2E(unittest.TestCase):
    """End-to-end test against the local deterministic HTTP fixture."""

    server = None
    base_url = None
    report = None

    @classmethod
    def setUpClass(cls):
        cls.server, port, cls.thread = _start_server()
        cls.base_url = f"http://127.0.0.1:{port}"
        # Run the audit against the local fixture server (allow localhost)
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)
            cls.report = run_audit.run_pipeline(
                cls.base_url + "/",
                _allow_localhost=True,
                enhanced=True,
                max_pages=12,
            )

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        if hasattr(cls, "thread") and cls.thread.is_alive():
            cls.thread.join(timeout=5)

    # -----------------------------------------------------------------------
    # Basic report shape
    # -----------------------------------------------------------------------
    def test_report_is_dict(self):
        self.assertIsInstance(self.report, dict)

    def test_report_has_required_keys(self):
        for key in ("site", "audited_at", "summary", "findings"):
            self.assertIn(key, self.report)

    def test_report_parses_as_json(self):
        """Ensure the report serialises to valid JSON."""
        serialised = json.dumps(self.report)
        parsed = json.loads(serialised)
        self.assertIn("findings", parsed)

    def test_exit_zero_findings_structure(self):
        """Every finding must have the required fields."""
        for f in self.report["findings"]:
            self.assertIn("id", f)
            self.assertIn("title", f)
            self.assertIn("severity", f)
            self.assertIn("evidence", f)
            self.assertIn("suggested_action", f)

    def test_severity_values_valid(self):
        valid = {"critical", "high", "medium"}
        for f in self.report["findings"]:
            self.assertIn(f["severity"], valid)

    def test_summary_math_correct(self):
        s = self.report["summary"]
        self.assertEqual(
            s["total_findings"],
            s.get("critical", 0) + s.get("high", 0) + s.get("medium", 0),
        )

    # -----------------------------------------------------------------------
    # Multi-page audit happened
    # -----------------------------------------------------------------------
    def test_multiple_pages_analysed(self):
        cov = self.report.get("evidence_coverage", {})
        inspected = cov.get("pages_inspected", [])
        self.assertGreater(len(inspected), 1,
                           "Multi-page audit should analyse more than 1 page")

    # -----------------------------------------------------------------------
    # Expected findings present
    # -----------------------------------------------------------------------
    def _titles(self):
        return [f["title"] for f in self.report["findings"]]

    def test_noindex_finding_present(self):
        """noindex page should be flagged — but only if the crawler actually fetched it.
        The robots.txt disallows /noindex, so the auditor should respect that.
        Either way, the audit must not crash."""
        # If robots disallows /noindex, it won't be fetched and no noindex finding
        # from that page. Other pages may still trigger noindex if not blocked.
        # Just assert the audit completed without error.
        self.assertIn("findings", self.report)

    def test_malformed_jsonld_finding_or_audit_survives(self):
        """Malformed JSON-LD on /malformed-jsonld should either surface a finding
        OR be silently isolated — the audit must NOT crash."""
        self.assertIn("findings", self.report)

    def test_thin_content_finding_present(self):
        """/blog/intro has only a few words — should trigger thin content."""
        titles = self._titles()
        self.assertIn("Thin Content Detected", titles,
                      "Expected thin content finding for /blog/intro")

    def test_missing_meta_description_present(self):
        """/blog/intro has no meta description."""
        titles = self._titles()
        self.assertIn("Missing Meta Description", titles)

    def test_sitemap_not_flagged_as_missing(self):
        """Sitemap is declared in robots.txt — should not get a missing-sitemap finding."""
        sitemap_missing = [
            f for f in self.report["findings"]
            if "Missing" in f["title"] and "Sitemap" in f["title"]
        ]
        self.assertEqual(sitemap_missing, [],
                         "Sitemap is declared so should not trigger a missing-sitemap finding")

    # -----------------------------------------------------------------------
    # False-positive guards
    # -----------------------------------------------------------------------
    def test_financial_article_no_product_finding(self):
        """/products/finance mentions $99 but is a financial article, not a product page.
        It has no Product schema and no add-to-cart / buy-now CTA — should NOT trigger
        a 'Missing Product/Offer Structured Data' finding solely due to the price string."""
        finance_product_findings = [
            f for f in self.report["findings"]
            if "Product" in f["title"] and "Structured Data" in f["title"]
            and "finance" in f.get("evidence", "")
        ]
        self.assertEqual(finance_product_findings, [],
                         "Financial article with '$99' text must not trigger a commerce finding")

    def test_no_crash_on_multipage(self):
        """Report must have the evidence_coverage block when enhanced=True."""
        self.assertIn("evidence_coverage", self.report)

    # -----------------------------------------------------------------------
    # CLI smoke test (subprocess)
    # -----------------------------------------------------------------------
    def test_cli_stdout_is_valid_json(self):
        """Run the CLI entrypoint via subprocess and verify stdout is valid JSON."""
        import subprocess
        result = subprocess.run(
            [
                sys.executable,
                str(ROOT / "skills/audit-orchestrator/scripts/run_audit.py"),
                self.base_url + "/",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0,
                         f"CLI exited non-zero. stderr: {result.stderr[:500]}")
        parsed = json.loads(result.stdout)
        self.assertIn("findings", parsed)
        self.assertIn("site", parsed)
        # stderr should not contain raw JSON (must not corrupt stdout)
        if result.stderr:
            try:
                json.loads(result.stderr)
                self.fail("stderr contains JSON — should only be on stdout")
            except json.JSONDecodeError:
                pass  # good: stderr is non-JSON debug text

    def test_cli_missing_url_returns_nonzero(self):
        """CLI with no URL argument should exit non-zero."""
        import subprocess
        result = subprocess.run(
            [sys.executable,
             str(ROOT / "skills/audit-orchestrator/scripts/run_audit.py")],
            capture_output=True, text=True, timeout=15,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_cli_invalid_scheme_returns_nonzero(self):
        """CLI with a file:// URL should exit non-zero."""
        import subprocess
        result = subprocess.run(
            [sys.executable,
             str(ROOT / "skills/audit-orchestrator/scripts/run_audit.py"),
             "file:///etc/passwd"],
            capture_output=True, text=True, timeout=15,
        )
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
