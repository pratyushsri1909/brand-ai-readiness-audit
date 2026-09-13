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
SPEC = importlib.util.spec_from_file_location("schema_detector", ROOT / "skills/structured-data-freshness/scripts/detector.py")
schema = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(schema)


class TestStructuredData(unittest.TestCase):
    def audit(self, html, headers=None, page_role=None):
        artifact = {"url":"https://site.test/page","html":html,"headers":headers or {}}
        if page_role:
            artifact["page_role"] = page_role
            artifact["page_intent"] = page_role
        return schema.audit(artifact)["findings"]

    def test_valid_object(self): self.assertEqual(schema.extract_json_ld_objects('<script type="application/ld+json">{"@type":"Organization"}</script>')[1], 0)
    def test_valid_array(self): self.assertEqual(len(schema.extract_json_ld_objects('<script type="application/ld+json">[{"@type":"Organization"},{"@type":"Product"}]</script>')[0]), 2)
    def test_valid_graph(self): self.assertEqual(len(schema.extract_json_ld_objects('<script type="application/ld+json">{"@graph":[{"@type":"Organization"},{"@type":"WebSite"}]}</script>')[0]), 2)
    def test_scalar_number(self): self.assertEqual(schema.extract_json_ld_objects('<script type="application/ld+json">42</script>')[0], [])
    def test_scalar_string(self): self.assertEqual(schema.extract_json_ld_objects('<script type="application/ld+json">"hello"</script>')[0], [])
    def test_scalar_null(self): self.assertEqual(schema.extract_json_ld_objects('<script type="application/ld+json">null</script>')[0], [])
    def test_scalar_boolean(self): self.assertEqual(schema.extract_json_ld_objects('<script type="application/ld+json">true</script>')[0], [])
    def test_malformed(self): self.assertEqual(schema.extract_json_ld_objects('<script type="application/ld+json">{"x":</script>')[1], 1)
    def test_mixed_page_preserves_valid(self):
        html='<script type="application/ld+json">{"x":</script><script type="application/ld+json">{"@type":"Product"}</script>'
        objs,bad,total=schema.extract_json_ld_objects(html)
        self.assertEqual(len(objs),1); self.assertEqual(bad,1); self.assertEqual(total,2)
    def test_no_jsonld_finding(self): self.assertTrue(any("Missing JSON-LD" in f["title"] for f in self.audit("<html></html>")))
    def test_jsonld_present_no_missing(self): self.assertFalse(any("Missing JSON-LD" in f["title"] for f in self.audit('<script type="application/ld+json">{"@type":"WebSite"}</script>')))
    def test_malformed_finding(self): self.assertTrue(any("Malformed JSON-LD" in f["title"] for f in self.audit('<script type="application/ld+json">{"x":</script>')))
    def test_product_schema(self): self.assertFalse(any("Product/Offer" in f["title"] for f in self.audit('<script type="application/ld+json">{"@type":"Product"}</script>')))
    def test_offer_schema(self): self.assertFalse(any("Product/Offer" in f["title"] for f in self.audit('<script type="application/ld+json">{"@type":"Offer"}</script>')))
    def test_price_only_no_false_positive(self): self.assertFalse(any("Product/Offer" in f["title"] for f in self.audit("Shares trade at $99 today.")))
    def test_price_article_no_false_positive(self): self.assertFalse(any("Product/Offer" in f["title"] for f in self.audit("The price rose from $50 to $99 in the market.")))
    def test_price_plus_cta(self):
        fs=self.audit("Widget $99 <button>Add to Cart</button> product", page_role="product")
        self.assertTrue(any("Product/Offer" in f["title"] for f in fs))
    def test_inr_plus_buy_now(self):
        fs=self.audit("Product ₹8500 <button>Buy Now</button> SKU 123", page_role="product")
        self.assertTrue(any("Product/Offer" in f["title"] for f in fs))
    def test_euro_price_without_cta(self): self.assertFalse(any("Product/Offer" in f["title"] for f in self.audit("Product €99")))
    def test_cta_without_price(self): self.assertFalse(any("Product/Offer" in f["title"] for f in self.audit("<button>Buy Now</button> Product")))
    def test_cta_and_price_without_context(self): self.assertFalse(any("Product/Offer" in f["title"] for f in self.audit("$99 <button>Buy Now</button>")))

    def test_editorial_price_and_purchase_language_no_commerce_finding(self):
        html = """<html><head><title>Market News</title></head><body>
        <article><h1>Retail market outlook</h1>
        <p>Analysts expect prices to rise. The purchase index was higher after the latest report.</p>
        <a href="/subscribe">Subscribe now</a></article></body></html>"""
        findings = schema.audit({
            "url": "https://news.test/story", "html": html, "page_role": "article",
            "page_intent": "article", "status_code": 200, "content_type": "text/html"
        })["findings"]
        self.assertFalse(any(f.get("rule_id") == "SD-COMMERCE-001" for f in findings))

    def test_help_returns_page_no_commerce_finding(self):
        html = """<html><body><h1>Returns and payment help</h1>
        <p>Payment methods, returns, refunds and purchase support. Product prices may vary.</p>
        <button>Contact support</button></body></html>"""
        findings = schema.audit({
            "url": "https://shop.test/help/returns", "html": html,
            "page_role": "faq", "page_intent": "faq", "status_code": 200, "content_type": "text/html"
        })["findings"]
        self.assertFalse(any(f.get("rule_id") == "SD-COMMERCE-001" for f in findings))

    def test_product_page_without_schema_still_gets_commerce_finding(self):
        html = """<html><body><h1>Acme Runner 2</h1>
        <p>Model Acme Runner 2. Price $129. SKU RUN2. In stock.</p>
        <button>Add to Cart</button></body></html>"""
        findings = schema.audit({
            "url": "https://shop.test/product/acme-runner-2", "html": html,
            "page_role": "product", "page_intent": "product", "status_code": 200, "content_type": "text/html"
        })["findings"]
        self.assertTrue(any(f.get("rule_id") == "SD-COMMERCE-001" for f in findings))

    def test_article_date_published(self):
        html='<script type="application/ld+json">{"@type":"Article","datePublished":"2026-01-01"}</script>'
        self.assertFalse(any("Freshness" in f["title"] for f in self.audit(html)))
    def test_article_date_modified(self):
        html='<script type="application/ld+json">{"@type":"Article","dateModified":"2026-01-01"}</script>'
        self.assertFalse(any("Freshness" in f["title"] for f in self.audit(html)))
    def test_article_last_modified_header(self):
        html='<script type="application/ld+json">{"@type":"Article"}</script>'
        self.assertFalse(any("Freshness" in f["title"] for f in self.audit(html,{"Last-Modified":"Wed, 01 Jan 2026 00:00:00 GMT"})))
    def test_article_missing_freshness(self):
        html='<script type="application/ld+json">{"@type":"Article"}</script>'
        self.assertTrue(any("Freshness" in f["title"] for f in self.audit(html)))
    def test_newsarticle_missing_freshness(self):
        html='<script type="application/ld+json">{"@type":"NewsArticle"}</script>'
        self.assertTrue(any("Freshness" in f["title"] for f in self.audit(html)))
    def test_blogposting_missing_freshness(self):
        html='<script type="application/ld+json">{"@type":"BlogPosting"}</script>'
        self.assertTrue(any("Freshness" in f["title"] for f in self.audit(html)))
    def test_org_with_id_and_sameas(self):
        html='<link rel="canonical" href="https://site.test/page"><script type="application/ld+json">{"@type":"Organization","@id":"https://site.test/#org","url":"https://site.test","sameAs":["https://social.example/org"]}</script>'
        self.assertFalse(any("Disambiguation" in f["title"] for f in self.audit(html)))
    def test_org_missing_identity(self):
        html='<script type="application/ld+json">{"@type":"Organization","name":"Acme"}</script>'
        self.assertTrue(any("Disambiguation" in f["title"] for f in self.audit(html)))
    def test_duplicate_org_without_ids(self):
        html='<script type="application/ld+json">[{"@type":"Organization","name":"A"},{"@type":"Organization","name":"B"}]</script>'
        self.assertTrue(any("Ambiguous Duplicate" in f["title"] for f in self.audit(html)))
    def test_duplicate_org_with_ids(self):
        html='<script type="application/ld+json">[{"@type":"Organization","@id":"https://site.test/#a"},{"@type":"Organization","@id":"https://site.test/#b"}]</script>'
        self.assertFalse(any("Ambiguous Duplicate" in f["title"] for f in self.audit(html)))
    def test_org_url_same_host(self):
        html='<link rel="canonical" href="https://site.test/page"><script type="application/ld+json">{"@type":"Organization","url":"https://site.test","@id":"x"}</script>'
        self.assertFalse(any("Conflicts With Canonical" in f["title"] for f in self.audit(html)))
    def test_org_url_other_host(self):
        html='<link rel="canonical" href="https://site.test/page"><script type="application/ld+json">{"@type":"Organization","url":"https://other.test","@id":"x"}</script>'
        self.assertTrue(any("Conflicts With Canonical" in f["title"] for f in self.audit(html)))
    def test_non_dict_graph_items_skipped(self):
        html='<script type="application/ld+json">{"@graph":[null,"x",42,{"@type":"Organization","@id":"x"}]}</script>'
        objs,bad,total=schema.extract_json_ld_objects(html)
        self.assertEqual(len(objs),1); self.assertEqual(bad,0); self.assertEqual(total,1)

    def test_stale_content_date(self):
        html = '<script type="application/ld+json">{"@type":"Article","dateModified":"2023-01-01"}</script>'
        fs = self.audit(html)
        stale = [f for f in fs if "Stale Content" in f["title"]]
        self.assertEqual(len(stale), 1)
        self.assertEqual(stale[0]["severity"], "medium")

    def test_future_content_date(self):
        html = '<script type="application/ld+json">{"@type":"Article","dateModified":"2028-01-01"}</script>'
        fs = self.audit(html)
        future = [f for f in fs if "Future Publication Date" in f["title"]]
        self.assertEqual(len(future), 1)

    def test_malformed_content_date(self):
        html = '<script type="application/ld+json">{"@type":"Article","dateModified":"not-a-valid-date"}</script>'
        fs = self.audit(html)
        unparseable = [f for f in fs if "Unparseable Content Timestamp" in f["title"]]
        self.assertEqual(len(unparseable), 1)

    def test_date_modified_earlier_than_published(self):
        html = '<script type="application/ld+json">{"@type":"Article","datePublished":"2026-06-01","dateModified":"2025-01-01"}</script>'
        fs = self.audit(html)
        contradictory = [f for f in fs if "Contradictory Publication" in f["title"]]
        self.assertEqual(len(contradictory), 1)
