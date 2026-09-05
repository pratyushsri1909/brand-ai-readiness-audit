"""
tests/test_unseen_generalization_matrix.py
Generalization Regression Matrix for previously unseen / unfamiliar website structures.

Covers 20 archetypes:
 1. static brochure
 2. SPA empty shell
 3. e-commerce
 4. SaaS with non-standard pricing URL
 5. local business
 6. documentation site
 7. single-page app
 8. Spanish/German navigation
 9. query-heavy routing
10. redirect-heavy site
11. 403/challenge response
12. JSON-LD-heavy site
13. image-heavy site
14. SVG-heavy site
15. site with no pricing
16. site with no About page
17. unusual CTA wording
18. inconsistent facts
19. JS-only critical content
20. well-structured healthy site with few/no findings.
"""
import importlib.util
import json
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

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "run_audit",
    ROOT / "skills/audit-orchestrator/scripts/run_audit.py",
)
run_audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(run_audit)


class MockResponse:
    def __init__(self, content, status=200, url="http://site.test/", headers=None):
        self._content = content.encode("utf-8") if isinstance(content, str) else content
        self.status = status
        self.url = url
        self.headers = headers or {"Content-Type": "text/html; charset=utf-8"}

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
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


def make_site_mock(pages, robots="User-agent: *\nAllow: /\n"):
    """Helper to mock _open_url and robots.txt for a synthetic site."""
    def mock_open(req, timeout=10):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        if url.endswith("/robots.txt"):
            return MockResponse(robots, 200, url, {"Content-Type": "text/plain"})
        if url in pages:
            data = pages[url]
            if isinstance(data, tuple):
                body, status, ctype = data[0], data[1], data[2] if len(data) > 2 else "text/html"
                return MockResponse(body, status, url, {"Content-Type": ctype})
            return MockResponse(data, 200, url, {"Content-Type": "text/html"})
        return MockResponse("<html><body><h1>Not Found</h1></body></html>", 404, url)
    return mock_open


class TestGeneralizationMatrix(unittest.TestCase):
    """Verifies audit performance across 20 distinct unfamiliar website archetypes."""

    # 1. Static brochure
    def test_01_static_brochure(self):
        pages = {
            "https://brochure.test/": """<!DOCTYPE html><html><head><title>Artisan Bakery</title>
            <meta name="description" content="Handcrafted sourdough breads and pastries in downtown.">
            </head><body><header><nav><a href="/menu">Our Breads</a><a href="/contact">Visit Us</a></nav></header>
            <main><h1>Artisan Sourdough Bakery</h1><p>Freshly baked every morning with local organic grains.</p>
            <a href="/contact">Order Ahead</a></main></body></html>""",
            "https://brochure.test/menu": """<!DOCTYPE html><html><head><title>Bakery Menu</title>
            <meta name="description" content="Sourdough loaves, croissants, and seasonal pastries.">
            </head><body><h1>Daily Offerings</h1><p>Country Loaf, Baguettes, Pain au Chocolat, and Scones.</p></body></html>""",
            "https://brochure.test/contact": """<!DOCTYPE html><html><head><title>Visit Us</title>
            <meta name="description" content="Hours and directions for our bakery shop.">
            </head><body><h1>Find Our Shop</h1><p>Open Tuesday through Sunday 7am to 2pm.</p></body></html>""",
        }
        with patch.object(run_audit, "_open_url", side_effect=make_site_mock(pages)):
            report = run_audit.run_pipeline("https://brochure.test/", enhanced=True, max_pages=5)
        self.assertIn("findings", report)
        self.assertIn(report["coverage"]["stop_reason"], ("source_exhaustion", "crawl_complete", "page_budget_exhausted"))
        critical_findings = [f for f in report["findings"] if f["severity"] == "critical"]
        self.assertEqual(len(critical_findings), 0)

    # 2. SPA empty shell
    def test_02_spa_empty_shell(self):
        pages = {
            "https://spa-shell.test/": """<!DOCTYPE html><html><head><title>Modern App</title>
            <script src="/bundle.js"></script></head><body><div id="root"></div></body></html>"""
        }
        with patch.object(run_audit, "_open_url", side_effect=make_site_mock(pages)):
            report = run_audit.run_pipeline("https://spa-shell.test/", enhanced=True, max_pages=3)
        rule_ids = [f.get("rule_id") for f in report["findings"]]
        # SPA shell with no text should trigger render gap or SPA detection without crashing
        self.assertTrue(any("SPA" in r or "RENDER" in r or "THIN" in r for r in rule_ids if r))

    # 3. E-commerce
    def test_03_ecommerce(self):
        pages = {
            "https://shop.test/": """<!DOCTYPE html><html><head><title>Urban Footwear</title>
            <meta name="description" content="Sustainable sneakers made from recycled ocean plastic.">
            </head><body><h1>Sustainable Footwear</h1><a href="/p/sneaker-01">Eco Runner One</a></body></html>""",
            "https://shop.test/p/sneaker-01": """<!DOCTYPE html><html><head><title>Eco Runner One - $120</title>
            <meta name="description" content="High performance recycled sneaker.">
            <script type="application/ld+json">
            {"@context":"https://schema.org","@type":"Product","name":"Eco Runner One","offers":{"@type":"Offer","price":"120.00","priceCurrency":"USD"}}
            </script></head><body><h1>Eco Runner One</h1><p>Price: $120.00</p><button>Add to Cart</button></body></html>""",
        }
        with patch.object(run_audit, "_open_url", side_effect=make_site_mock(pages)):
            report = run_audit.run_pipeline("https://shop.test/", enhanced=True, max_pages=3)
        self.assertTrue(report["coverage"]["urls_fetched"] >= 2)
        commerce_absent = [f for f in report["findings"] if f.get("rule_id") == "SD-COMMERCE-001"]
        self.assertEqual(len(commerce_absent), 0)

    # 4. SaaS with non-standard pricing URL
    def test_04_saas_nonstandard_pricing(self):
        pages = {
            "https://cloud.test/": """<!DOCTYPE html><html><head><title>DevOps Pipeline Cloud</title>
            <meta name="description" content="Automated continuous integration platform.">
            </head><body><h1>Continuous Integration Platform</h1><nav>
            <a href="/tiers-and-investment">Tiers and Investment</a><a href="/solutions">Solutions</a>
            </nav><a href="/get-started">Start 14-Day Free Trial</a></body></html>""",
            "https://cloud.test/tiers-and-investment": """<!DOCTYPE html><html><head><title>Investment Plans</title>
            <meta name="description" content="Pricing tiers for teams and enterprises.">
            </head><body><h1>Choose Your Plan</h1><p>Starter $29/mo, Scale $99/mo, Enterprise Custom.</p></body></html>""",
        }
        with patch.object(run_audit, "_open_url", side_effect=make_site_mock(pages)):
            report = run_audit.run_pipeline("https://cloud.test/", enhanced=True, max_pages=5)
        self.assertTrue(report["coverage"]["urls_fetched"] >= 2)
        self.assertIn("findings", report)

    # 5. Local business
    def test_05_local_business(self):
        pages = {
            "https://plumber.test/": """<!DOCTYPE html><html><head><title>Apex Plumbing Denver</title>
            <meta name="description" content="Licensed commercial and residential plumbing services.">
            <script type="application/ld+json">
            {"@context":"https://schema.org","@type":"Plumber","name":"Apex Plumbing","telephone":"+1-303-555-0199","address":{"@type":"PostalAddress","addressLocality":"Denver","addressRegion":"CO"}}
            </script></head><body><h1>Denver Emergency Plumbing</h1><p>Fast 24/7 service.</p><a href="/book">Book Now</a></body></html>"""
        }
        with patch.object(run_audit, "_open_url", side_effect=make_site_mock(pages)):
            report = run_audit.run_pipeline("https://plumber.test/", enhanced=True, max_pages=3)
        self.assertIn(report["coverage"]["stop_reason"], ("source_exhaustion", "crawl_complete", "page_budget_exhausted"))
        missing_org = [f for f in report["findings"] if f.get("rule_id") == "SD-ORG-MISSING-001"]
        self.assertEqual(len(missing_org), 0)

    # 6. Documentation site
    def test_06_documentation_site(self):
        pages = {
            "https://docs.test/": """<!DOCTYPE html><html><head><title>API Reference Manual</title>
            <meta name="description" content="Complete documentation and reference for our SDK.">
            </head><body><h1>API Reference Documentation</h1><nav>
            <a href="/v1/auth">Authentication</a><a href="/v1/endpoints">Endpoints</a>
            </nav><pre><code>curl -H "Authorization: Bearer KEY" https://api.test/v1</code></pre></body></html>""",
            "https://docs.test/v1/auth": """<!DOCTYPE html><html><head><title>Auth Guide</title>
            <meta name="description" content="OAuth2 flow documentation.">
            </head><body><h1>OAuth Authentication</h1><p>Detailed token exchange flows.</p></body></html>""",
        }
        with patch.object(run_audit, "_open_url", side_effect=make_site_mock(pages)):
            report = run_audit.run_pipeline("https://docs.test/", enhanced=True, max_pages=5)
        self.assertTrue(report["coverage"]["urls_fetched"] >= 2)

    # 7. Single-page app (anchor navigation)
    def test_07_single_page_app(self):
        pages = {
            "https://onepage.test/": """<!DOCTYPE html><html><head><title>Modern Studio</title>
            <meta name="description" content="Creative branding and interactive 3D web experiences.">
            </head><body><nav><a href="#about">About</a><a href="#services">Services</a><a href="#contact">Contact</a></nav>
            <section id="about"><h1>About Creative Studio</h1><p>We craft digital experiences.</p></section>
            <section id="services"><h2>Services</h2><p>Design, Architecture, Strategy.</p></section>
            <section id="contact"><h2>Contact</h2><a href="mailto:hello@studio.test">Work With Us</a></section></body></html>"""
        }
        with patch.object(run_audit, "_open_url", side_effect=make_site_mock(pages)):
            report = run_audit.run_pipeline("https://onepage.test/", enhanced=True, max_pages=3)
        self.assertIn(report["coverage"]["stop_reason"], ("source_exhaustion", "crawl_complete", "page_budget_exhausted"))

    # 8. Spanish/German navigation
    def test_08_multilingual_navigation(self):
        pages = {
            "https://polyglot.test/": """<!DOCTYPE html><html><head><title>Soluciones Globales</title>
            <meta name="description" content="Plataforma empresarial para la gestión inteligente de datos.">
            </head><body><header><nav><a href="/preise">Preise und Tarife</a><a href="/contacto">Contacto</a></nav></header>
            <main><h1>Gestión de Datos Empresarial</h1><p>Optimice sus procesos en tiempo real con nuestra tecnología.</p>
            <a href="/contacto">Comenzar Ahora</a></main></body></html>""",
            "https://polyglot.test/preise": """<!DOCTYPE html><html><head><title>Preise Übersicht</title>
            <meta name="description" content="Unsere flexiblen Abonnement-Modelle für alle Unternehmensgrößen.">
            </head><body><h1>Transparente Preise</h1><p>Basispaket 50€ monatlich, Profi 150€ monatlich.</p>
            <a href="/anmelden">Jetzt Kaufen</a></body></html>""",
        }
        with patch.object(run_audit, "_open_url", side_effect=make_site_mock(pages)):
            report = run_audit.run_pipeline("https://polyglot.test/", enhanced=True, max_pages=5)
        # Should recognize multilingual CTA and not emit false missing CTA
        cta_findings = [f for f in report["findings"] if f.get("rule_id") == "ENG-CTA-MISSING-001"]
        self.assertEqual(len(cta_findings), 0)

    # 9. Query-heavy routing
    def test_09_query_heavy_routing(self):
        pages = {
            "https://legacy.test/": """<!DOCTYPE html><html><head><title>Enterprise Gateway</title>
            <meta name="description" content="Enterprise portal for operations management.">
            </head><body><h1>Operations Gateway</h1><a href="/index.php?action=view&sec=about">About</a>
            <a href="/index.php?action=view&sec=products">Products</a></body></html>""",
            "https://legacy.test/index.php?action=view&sec=about": """<!DOCTYPE html><html><head><title>Company Story</title>
            <meta name="description" content="Learn about our 30-year legacy in logistics.">
            </head><body><h1>About Our Logistics Network</h1><p>Decades of dependable transport.</p></body></html>""",
        }
        with patch.object(run_audit, "_open_url", side_effect=make_site_mock(pages)):
            report = run_audit.run_pipeline("https://legacy.test/", enhanced=True, max_pages=5)
        self.assertTrue(report["coverage"]["urls_fetched"] >= 2)

    # 10. Redirect-heavy site
    def test_10_redirect_heavy_site(self):
        def mock_redirects(req, timeout=10):
            url = req.full_url if hasattr(req, "full_url") else str(req)
            if url.endswith("/robots.txt"):
                return MockResponse("User-agent: *\nAllow: /\n", 200, url, {"Content-Type": "text/plain"})
            if url == "https://chain.test/":
                return MockResponse("", 301, url, {"Location": "https://chain.test/r1"})
            if url == "https://chain.test/r1":
                return MockResponse("", 302, url, {"Location": "https://chain.test/final"})
            if url == "https://chain.test/final":
                return MockResponse("""<!DOCTYPE html><html><head><title>Final Destination</title>
                <meta name="description" content="You have arrived at the ultimate destination page.">
                </head><body><h1>Arrived Safely</h1><p>Redirect chain resolved successfully.</p></body></html>""", 200, url)
            return MockResponse("404", 404, url)

        with patch.object(run_audit, "_open_url", side_effect=mock_redirects):
            report = run_audit.run_pipeline("https://chain.test/", enhanced=True, max_pages=3)
        self.assertEqual(report["coverage"]["urls_fetched"], 1)

    # 11. 403 / challenge response
    def test_11_forbidden_challenge_response(self):
        pages = {
            "https://blocked.test/": ("""<!DOCTYPE html><html><head><title>Access Denied</title></head>
            <body><h1>403 Forbidden - Bot Challenge</h1><p>Please solve the captcha.</p></body></html>""", 403, "text/html")
        }
        with patch.object(run_audit, "_open_url", side_effect=make_site_mock(pages)):
            report = run_audit.run_pipeline("https://blocked.test/", enhanced=True, max_pages=3)
        # Must not crash or raise false absence findings (like missing H1 or missing CTA) for blocked pages
        self.assertIn("findings", report)
        h1_absent = [f for f in report["findings"] if f.get("rule_id") == "ENG-H1-ZERO-001"]
        self.assertEqual(len(h1_absent), 0)

    # 12. JSON-LD heavy site
    def test_12_jsonld_heavy_site(self):
        pages = {
            "https://semantic.test/": """<!DOCTYPE html><html><head><title>Knowledge Graph Media</title>
            <meta name="description" content="Comprehensive journalism backed by linked data.">
            <script type="application/ld+json">
            {
              "@context": "https://schema.org",
              "@graph": [
                {"@type": "NewsMediaOrganization", "name": "KG Media", "url": "https://semantic.test/"},
                {"@type": "WebSite", "name": "KG Media Portal", "url": "https://semantic.test/"}
              ]
            }
            </script></head><body><h1>Linked Data Newsroom</h1><p>Journalism grounded in verified facts.</p>
            <a href="/subscribe">Subscribe Today</a></body></html>"""
        }
        with patch.object(run_audit, "_open_url", side_effect=make_site_mock(pages)):
            report = run_audit.run_pipeline("https://semantic.test/", enhanced=True, max_pages=3)
        syntax_errs = [f for f in report["findings"] if f.get("rule_id") == "SD-SYNTAX-001"]
        self.assertEqual(len(syntax_errs), 0)

    # 13. Image-heavy site
    def test_13_image_heavy_site(self):
        pages = {
            "https://gallery.test/": """<!DOCTYPE html><html><head><title>Wildlife Photo Gallery</title>
            <meta name="description" content="Stunning high-resolution photography of arctic wildlife.">
            </head><body><h1>Arctic Explorations</h1>
            <img src="/polar-bear.jpg" alt="Polar bear on sea ice in Svalbard">
            <img src="/arctic-fox.jpg" alt="Arctic fox running in snow">
            <p>Photographed during the 2025 Svalbard Research Expedition.</p>
            <a href="/prints">Buy Limited Edition Prints</a></body></html>"""
        }
        with patch.object(run_audit, "_open_url", side_effect=make_site_mock(pages)):
            report = run_audit.run_pipeline("https://gallery.test/", enhanced=True, max_pages=3)
        nontext_errs = [f for f in report["findings"] if f.get("rule_id") == "SD-NONTEXT-001"]
        self.assertEqual(len(nontext_errs), 0)

    # 14. SVG-heavy site
    def test_14_svg_heavy_site(self):
        pages = {
            "https://vectors.test/": """<!DOCTYPE html><html><head><title>Vector Design Studio</title>
            <meta name="description" content="Accessible scalable vector graphics for modern design systems.">
            </head><body><h1>Scalable Icons Studio</h1>
            <svg aria-hidden="true" width="24" height="24"><path d="M0 0h24v24H0z"/></svg>
            <svg role="img" aria-label="Company Brand Logo" width="100" height="40"><circle cx="20" cy="20" r="10"/></svg>
            <p>Our icons comply strictly with accessibility standards.</p><a href="/contact">Get in Touch</a></body></html>"""
        }
        with patch.object(run_audit, "_open_url", side_effect=make_site_mock(pages)):
            report = run_audit.run_pipeline("https://vectors.test/", enhanced=True, max_pages=3)
        # Decorative svg with aria-hidden is ignored, logo has aria-label, so no SD-NONTEXT-001 finding
        nontext_errs = [f for f in report["findings"] if f.get("rule_id") == "SD-NONTEXT-001"]
        self.assertEqual(len(nontext_errs), 0)

    # 15. Site with no pricing
    def test_15_site_with_no_pricing(self):
        pages = {
            "https://agency.test/": """<!DOCTYPE html><html><head><title>Elite Strategic Advisory</title>
            <meta name="description" content="Bespoke advisory for Fortune 500 boardrooms and leadership.">
            </head><body><h1>Strategic Advisory Services</h1><p>We work exclusively on retained referral engagements.</p>
            <a href="/inquire">Submit Inquiry</a></body></html>"""
        }
        with patch.object(run_audit, "_open_url", side_effect=make_site_mock(pages)):
            report = run_audit.run_pipeline("https://agency.test/", enhanced=True, max_pages=3)
        # Non-commerce advisory site must not be penalized with false commerce schema findings
        commerce_findings = [f for f in report["findings"] if f.get("rule_id") == "SD-COMMERCE-001"]
        self.assertEqual(len(commerce_findings), 0)

    # 16. Site with no About page
    def test_16_site_with_no_about_page(self):
        pages = {
            "https://singletool.test/": """<!DOCTYPE html><html><head><title>Hash Generator Utility</title>
            <meta name="description" content="Instant client-side SHA-256 and SHA-512 hashing utility.">
            </head><body><h1>Client-Side Hash Generator</h1><p>Calculate cryptographically secure checksums in browser.</p>
            <button>Calculate Hash</button></body></html>"""
        }
        with patch.object(run_audit, "_open_url", side_effect=make_site_mock(pages)):
            report = run_audit.run_pipeline("https://singletool.test/", enhanced=True, max_pages=3)
        # Must execute cleanly to termination without crashing
        self.assertIn(report["coverage"]["stop_reason"], ("source_exhaustion", "crawl_complete", "page_budget_exhausted"))

    # 17. Unusual CTA wording
    def test_17_unusual_cta_wording(self):
        pages = {
            "https://cohort.test/": """<!DOCTYPE html><html><head><title>Leadership Fellowship</title>
            <meta name="description" content="An intensive twelve-week fellowship for emerging tech leaders.">
            </head><body><h1>Global Leadership Fellowship</h1><p>Apply for the upcoming autumn cohort.</p>
            <a href="/apply" class="button">Claim your spot</a></body></html>"""
        }
        with patch.object(run_audit, "_open_url", side_effect=make_site_mock(pages)):
            report = run_audit.run_pipeline("https://cohort.test/", enhanced=True, max_pages=3)
        cta_missing = [f for f in report["findings"] if f.get("rule_id") == "ENG-CTA-MISSING-001"]
        self.assertEqual(len(cta_missing), 0)

    # 18. Inconsistent facts
    def test_18_inconsistent_facts(self):
        pages = {
            "https://conflicts.test/": """<!DOCTYPE html><html><head><title>Gadget World</title>
            <meta name="description" content="Best gadgets and electronics.">
            <script type="application/ld+json">
            {"@context":"https://schema.org","@type":"Product","name":"Pro Drone","offers":{"@type":"Offer","price":"499.00","priceCurrency":"USD"}}
            </script></head><body><h1>Pro Drone v2</h1><p>Special sale price: $299 today only!</p>
            <button>Buy Now</button></body></html>"""
        }
        with patch.object(run_audit, "_open_url", side_effect=make_site_mock(pages)):
            report = run_audit.run_pipeline("https://conflicts.test/", enhanced=True, max_pages=3)
        # Fact mismatch should either be detected or handled gracefully without crash
        self.assertIn("findings", report)

    # 19. JS-only critical content
    def test_19_js_only_critical_content(self):
        pages = {
            "https://hydrate.test/": """<!DOCTYPE html><html><head><title>Client Portal</title></head>
            <body><div id="__next"></div><script>window.__DATA__ = {user: "anon"};</script></body></html>"""
        }
        with patch.object(run_audit, "_open_url", side_effect=make_site_mock(pages)):
            report = run_audit.run_pipeline("https://hydrate.test/", enhanced=True, max_pages=3)
        # Low content / JS shell should trigger thin content or hydration/render gap
        rule_ids = [f.get("rule_id") for f in report["findings"]]
        self.assertTrue(any("RENDER" in r or "THIN" in r for r in rule_ids if r))

    # 20. Well-structured healthy site
    def test_20_well_structured_healthy_site(self):
        pages = {
            "https://healthy.test/": """<!DOCTYPE html><html><head><title>Beacon Analytics Platform</title>
            <meta name="description" content="Privacy-first web traffic analytics and real-time behavioral insights.">
            <link rel="canonical" href="https://healthy.test/">
            <script type="application/ld+json">
            {"@context":"https://schema.org","@type":"Organization","name":"Beacon Analytics","url":"https://healthy.test/"}
            </script></head><body><header><nav><a href="/features">Features</a><a href="/pricing">Pricing</a></nav></header>
            <main><h1>Privacy-Preserving Web Analytics</h1><p>Gain actionable visitor metrics without cookies or personal data tracking.</p>
            <a href="/signup">Start Free Trial</a></main><footer><p>&copy; 2026 Beacon Analytics Inc.</p></footer></body></html>"""
        }
        with patch.object(run_audit, "_open_url", side_effect=make_site_mock(pages)):
            report = run_audit.run_pipeline("https://healthy.test/", enhanced=True, max_pages=3)
        self.assertIn(report["coverage"]["stop_reason"], ("source_exhaustion", "crawl_complete", "page_budget_exhausted"))
        criticals = [f for f in report["findings"] if f["severity"] == "critical"]
        highs = [f for f in report["findings"] if f["severity"] == "high"]
        self.assertEqual(len(criticals), 0)
        self.assertEqual(len(highs), 0)


if __name__ == "__main__":
    unittest.main()
