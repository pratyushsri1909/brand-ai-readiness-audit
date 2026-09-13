import http.server
import importlib.util
import socketserver
import threading
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

ROOT = Path(__file__).resolve().parents[1]
SPEC_RUN = importlib.util.spec_from_file_location("run_audit", ROOT / "skills/audit-orchestrator/scripts/run_audit.py")
run_audit = importlib.util.module_from_spec(SPEC_RUN)
SPEC_RUN.loader.exec_module(run_audit)

FIXTURE_PAGES = {
    "/robots.txt": ("text/plain", "User-agent: *\nAllow: /\nSitemap: /sitemap.xml\n"),
    "/sitemap.xml": ("application/xml", """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url><loc>/about</loc></url>
    <url><loc>/products/item-a</loc></url>
    <url><loc>/pricing</loc></url>
    <url><loc>/contact</loc></url>
</urlset>"""),
    "/": ("text/html", """<!DOCTYPE html>
<html>
<head><title>Acme Corporation - AI Powered Platforms</title><meta name="description" content="Acme builds next-gen software solutions."></head>
<body>
    <h1>Acme Corporation</h1>
    <nav>
        <a href="/about">About Us</a>
        <a href="/products/item-a">Product A</a>
        <a href="/products/item-b">Product B</a>
        <a href="/pricing">Pricing Plans</a>
        <a href="/contact">Contact Support</a>
        <a href="/blog/financial-report">Q4 Financial Update</a>
        <a href="/blog/article-1">Article One</a>
        <a href="/blog/article-1-dup">Article One Duplicate</a>
        <a href="/search?q=exploit">Search Trap</a>
        <a href="/a/b/a/b/a/b">Loop Trap</a>
        <a href="/brochure.pdf">Download PDF</a>
        <a href="/redirect-page">Redirect to Product A</a>
    </nav>
    <p>Discover our comprehensive suite of developer tools and cloud services.</p>
    <button>Get Started Now</button>
</body>
</html>"""),
    "/about": ("text/html", """<!DOCTYPE html>
<html>
<head><title>About Us - Acme Corporation</title><meta name="description" content="Learn about Acme team and mission."></head>
<body>
    <h1>About Acme Corporation</h1>
    <p>Founded in 2020, Acme Corporation has grown into a leader in AI tooling and cloud orchestration.</p>
    <a href="/contact">Get in Touch</a>
</body>
</html>"""),
    "/contact": ("text/html", """<!DOCTYPE html>
<html>
<head><title>Contact Us - Acme Corporation</title><meta name="description" content="Reach our support and sales teams."></head>
<body>
    <h1>Contact Our Team</h1>
    <p>Send an email to support@acme.test or call our sales line.</p>
    <a href="/pricing">View Pricing</a>
</body>
</html>"""),
    "/products/item-a": ("text/html", """<!DOCTYPE html>
<html>
<head>
    <title>Acme Cloud Engine - Product</title>
    <meta name="description" content="Acme Cloud Engine provides real-time scalable inference.">
    <script type="application/ld+json">
    {
        "@context": "https://schema.org",
        "@type": "Product",
        "name": "Acme Cloud Engine",
        "description": "High performance inference cluster",
        "offers": {
            "@type": "Offer",
            "price": "99.00",
            "priceCurrency": "USD"
        }
    }
    </script>
</head>
<body>
    <h1>Acme Cloud Engine</h1>
    <p>Scalable AI infrastructure for enterprise workloads. Pricing starts at $99.00 per month.</p>
    <button>Buy Now</button>
</body>
</html>"""),
    "/products/item-b": ("text/html", """<!DOCTYPE html>
<html>
<head>
    <title>Acme Edge Node - Product</title>
    <meta name="description" content="Acme Edge Node device.">
    <script type="application/ld+json">
    { malformed json block without closing quotes
    </script>
</head>
<body>
    <h1>Acme Edge Node</h1>
    <p>Edge hardware appliance for low latency inference.</p>
    <button>Order Device</button>
</body>
</html>"""),
    "/pricing": ("text/html", """<!DOCTYPE html>
<html>
<head><title>Pricing & Plans - Acme Corporation</title><meta name="description" content="Flexible pricing tiers for every team."></head>
<body>
    <h1>Transparent Pricing Plans</h1>
    <p>Starter Plan: $29/mo. Pro Plan: $99/mo. Enterprise Plan: Custom quote.</p>
    <a href="/contact">Request Enterprise Quote</a>
</body>
</html>"""),
    "/blog/financial-report": ("text/html", """<!DOCTYPE html>
<html>
<head><title>Q4 Financial Report - Acme News</title><meta name="description" content="Acme reports quarterly financial achievements."></head>
<body>
    <h1>Q4 Financial Overview</h1>
    <p>Annual revenue reached $99 million this fiscal year with remarkable growth across all enterprise segments.</p>
    <p>This report highlights corporate performance rather than consumer products.</p>
</body>
</html>"""),
    "/blog/article-1": ("text/html", """<!DOCTYPE html>
<html>
<head><title>Guide to Agentic Architecture - Acme Blog</title><meta name="description" content="Best practices for building autonomous agents."></head>
<body>
    <h1>Guide to Agentic Architecture</h1>
    <p>Building reliable agent workflows requires deterministic evaluation, bounded resource consumption, robust error isolation, and evidence-backed reasoning.</p>
</body>
</html>"""),
    "/blog/article-1-dup": ("text/html", """<!DOCTYPE html>
<html>
<head><title>Guide to Agentic Architecture Mirror - Acme Blog</title><meta name="description" content="Best practices for building autonomous agents mirror."></head>
<body>
    <h1>Guide to Agentic Architecture</h1>
    <p>Building reliable agent workflows requires deterministic evaluation, bounded resource consumption, robust error isolation, and evidence-backed reasoning.</p>
</body>
</html>"""),
}


class _AdversarialHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    def do_GET(self):
        path = self.path
        if path == "/redirect-page":
            self.send_response(302)
            self.send_header("Location", "/products/item-a")
            self.end_headers()
            return

        clean_path = path.split("?")[0]
        if clean_path in FIXTURE_PAGES:
            content_type, body = FIXTURE_PAGES[clean_path]
            data = body.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass  # Suppress console logging during test execution


class TestAdversarialFixtureE2E(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), _AdversarialHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        if hasattr(cls, "thread") and cls.thread.is_alive():
            cls.thread.join(timeout=5)

    def test_full_adversarial_crawl_and_audit(self):
        root_url = f"http://127.0.0.1:{self.port}/"
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)
            report = run_audit.run_pipeline(root_url, enhanced=True, max_pages=15, _allow_localhost=True)

        # 1. Verify schema compliance
        self.assertIn("site", report)
        self.assertIn("audited_at", report)
        self.assertIn("summary", report)
        self.assertIn("findings", report)
        self.assertIn("coverage", report)
        self.assertIn("evidence_coverage", report)
        self.assertIn("readiness_band", report)
        self.assertIn("executive_summary", report)

        # 2. Verify multi-page crawl coverage
        cov = report["coverage"]
        self.assertGreaterEqual(cov["pages_sampled"], 5)
        self.assertTrue(cov["crawl_completed"])

        # 3. Verify exact duplicate was detected between article-1 and article-1-dup
        finding_titles = [f["title"] for f in report["findings"]]
        self.assertIn("Exact Duplicate Content Detected", finding_titles)

        # 4. Verify malformed JSON-LD was flagged without breaking valid Product JSON-LD
        self.assertIn("Malformed JSON-LD Syntax", finding_titles)

        # 5. Verify no crash on non-HTML PDF or trap URLs
        for inspected in report["evidence_coverage"]["pages_inspected"]:
            self.assertFalse(inspected["url"].endswith(".pdf"))
            self.assertFalse("/a/b/a/b" in inspected["url"])


if __name__ == "__main__":
    unittest.main()
