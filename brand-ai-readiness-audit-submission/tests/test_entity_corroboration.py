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
SPEC = importlib.util.spec_from_file_location("entity_detector", ROOT / "skills/entity-corroboration-audit/scripts/detector.py")
entity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(entity)


class TestEntityCorroboration(unittest.TestCase):
    def test_consistent_organization(self):
        page1 = {
            "url": "https://example.com/",
            "html": '<script type="application/ld+json">{"@type":"Organization","@id":"https://example.com/#org","name":"Acme Corp","url":"https://example.com"}</script>'
        }
        page2 = {
            "url": "https://example.com/about",
            "html": '<script type="application/ld+json">{"@type":"Organization","@id":"https://example.com/#org","name":"Acme Corp","url":"https://example.com"}</script>'
        }
        res = entity.audit({"page_artifacts": [page1, page2]})
        self.assertEqual(res["findings"], [])

    def test_conflicting_organization_name_raises_finding(self):
        page1 = {
            "url": "https://example.com/",
            "html": '<script type="application/ld+json">{"@type":"Organization","@id":"https://example.com/#org","name":"Acme Corp","url":"https://example.com"}</script>'
        }
        page2 = {
            "url": "https://example.com/about",
            "html": '<script type="application/ld+json">{"@type":"Organization","@id":"https://example.com/#org","name":"Acme Global Solutions LLC","url":"https://example.com"}</script>'
        }
        res = entity.audit({"page_artifacts": [page1, page2]})
        conflicts = [f for f in res["findings"] if "Conflicting Organization Names" in f["title"]]
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["severity"], "high")
        self.assertIn("Acme Corp", conflicts[0]["evidence"])
        self.assertIn("Acme Global Solutions LLC", conflicts[0]["evidence"])

    def test_multibrand_distinct_organizations_not_conflicting(self):
        # Two distinct brand subsidiaries on the same site must NOT trigger a conflict finding
        page1 = {
            "url": "https://example.com/brand-a",
            "html": '<script type="application/ld+json">{"@type":"Organization","@id":"https://example.com/#brand-a","name":"Brand Alpha","url":"https://example.com/brand-a"}</script>'
        }
        page2 = {
            "url": "https://example.com/brand-b",
            "html": '<script type="application/ld+json">{"@type":"Organization","@id":"https://example.com/#brand-b","name":"Brand Beta","url":"https://example.com/brand-b"}</script>'
        }
        res = entity.audit({"page_artifacts": [page1, page2]})
        self.assertEqual(res["findings"], [])

    def test_conflicting_product_pricing(self):
        page1 = {
            "url": "https://example.com/products/superwidget",
            "html": '<script type="application/ld+json">{"@type":"Product","name":"SuperWidget","offers":{"@type":"Offer","price":"99.00"}}</script>'
        }
        page2 = {
            "url": "https://example.com/promo/superwidget",
            "html": '<script type="application/ld+json">{"@type":"Product","name":"SuperWidget","offers":{"@type":"Offer","price":"149.00"}}</script>'
        }
        res = entity.audit({"page_artifacts": [page1, page2]})
        conflicts = [f for f in res["findings"] if "Conflicting Product Pricing" in f["title"]]
        self.assertEqual(len(conflicts), 1)
        self.assertEqual(conflicts[0]["severity"], "high")
        self.assertIn("99.00", conflicts[0]["evidence"])
        self.assertIn("149.00", conflicts[0]["evidence"])

    def test_single_page_returns_empty_findings(self):
        page1 = {
            "url": "https://example.com/",
            "html": '<script type="application/ld+json">{"@type":"Organization","name":"Acme"}</script>'
        }
        res = entity.audit({"page_artifacts": [page1]})
        self.assertEqual(res["findings"], [])


if __name__ == "__main__":
    unittest.main()
