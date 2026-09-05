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

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("discovery_detector", ROOT / "skills/site-discovery-audit/scripts/detector.py")
discovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(discovery)


class TestSiteDiscovery(unittest.TestCase):
    def test_normalize_url_strips_tracking_and_fragment(self):
        raw = "https://example.com/page?utm_source=twitter&gclid=12345&real_param=value#section"
        norm = discovery.normalize_url(raw)
        self.assertEqual(norm, "https://example.com/page?real_param=value")

    def test_normalize_url_resolves_relative(self):
        norm = discovery.normalize_url("about.html", base_url="https://example.com/sub/index.html")
        self.assertEqual(norm, "https://example.com/sub/about.html")

    def test_parse_flat_sitemap(self):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
        <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <url><loc>https://example.com/</loc></url>
            <url><loc>https://example.com/about</loc></url>
            <url><loc>https://example.com/products/item1</loc></url>
        </urlset>"""
        urls, child_sms = discovery.parse_sitemap_xml(xml)
        self.assertEqual(len(urls), 3)
        self.assertEqual(child_sms, [])
        self.assertIn("https://example.com/about", urls)

    def test_parse_sitemap_index(self):
        xml = """<?xml version="1.0" encoding="UTF-8"?>
        <sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
            <sitemap><loc>https://example.com/sitemap-pages.xml</loc></sitemap>
            <sitemap><loc>https://example.com/sitemap-products.xml</loc></sitemap>
        </sitemapindex>"""
        urls, child_sms = discovery.parse_sitemap_xml(xml)
        self.assertEqual(urls, [])
        self.assertEqual(len(child_sms), 2)
        self.assertIn("https://example.com/sitemap-pages.xml", child_sms)

    def test_classify_url_roles(self):
        self.assertEqual(discovery.classify_url_role("https://example.com/")[0], "homepage")
        self.assertEqual(discovery.classify_url_role("https://example.com/about-us")[0], "about")
        self.assertEqual(discovery.classify_url_role("https://example.com/contact")[0], "contact")
        self.assertEqual(discovery.classify_url_role("https://example.com/products/widget")[0], "product")
        self.assertEqual(discovery.classify_url_role("https://example.com/blog/ai-trends")[0], "article")

    def test_role_left_unfilled_when_low_confidence(self):
        role, reason = discovery.classify_url_role("https://example.com/random-uuid-xyz-123")
        self.assertIsNone(role)
        self.assertIn("No definitive role", reason)

    def test_build_page_plan_budget_cap(self):
        candidates = [
            ("https://example.com/about", "About Us"),
            ("https://example.com/contact", "Contact"),
            ("https://example.com/products/item1", "Item 1"),
            ("https://example.com/products/item2", "Item 2"),
            ("https://example.com/blog/post1", "Post 1"),
            ("https://example.com/blog/post2", "Post 2"),
        ]
        plan, stopping_condition = discovery.build_page_plan(candidates, "https://example.com", budget=3)
        self.assertEqual(len(plan), 3)
        self.assertEqual(plan[0]["url"], "https://example.com/")
        self.assertEqual(stopping_condition, "budget_reached")

    def test_build_page_plan_source_exhaustion(self):
        candidates = [
            ("https://example.com/about", "About Us"),
        ]
        plan, stopping_condition = discovery.build_page_plan(candidates, "https://example.com", budget=5)
        self.assertEqual(len(plan), 2)  # Homepage + About
        self.assertEqual(stopping_condition, "source_exhaustion")

    def test_audit_missing_sitemap_finding(self):
        html = '<a href="/about">About</a><a href="/contact">Contact</a>'
        res = discovery.audit({"url": "https://example.com", "html": html, "robots_content": "User-agent: *\nAllow: /"})
        self.assertTrue(any("Missing or Inaccessible XML Sitemap" in f["title"] for f in res["findings"]))
        self.assertEqual(len(res["page_plan"]), 3)  # Homepage, About, Contact

    def test_audit_with_sitemap_xml(self):
        xml = '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>https://example.com/about</loc></url></urlset>'
        res = discovery.audit({
            "url": "https://example.com",
            "html": "",
            "robots_content": "User-agent: *\nAllow: /\nSitemap: https://example.com/sitemap.xml",
            "sitemap_xml": xml,
        })
        self.assertFalse(any("Missing or Inaccessible XML Sitemap" in f["title"] for f in res["findings"]))
        self.assertTrue(any(p["inferred_role"] == "about" for p in res["page_plan"]))


if __name__ == "__main__":
    unittest.main()
