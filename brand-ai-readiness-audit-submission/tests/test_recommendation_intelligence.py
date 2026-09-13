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

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("rules_mod", ROOT / "skills/audit-orchestrator/scripts/rules.py")
rules = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rules)


class TestRecommendationIntelligence(unittest.TestCase):
    def test_rule_matching_known_findings(self):
        rule_id, _ = rules.match_rule_for_finding("Noindex Directive Blocks Machine Indexing")
        self.assertEqual(rule_id, "CR-NOINDEX-001")

        rule_id, _ = rules.match_rule_for_finding("Missing JSON-LD Structured Data")
        self.assertEqual(rule_id, "SD-MISSING-001")

        rule_id, _ = rules.match_rule_for_finding("Missing Product/Offer Structured Data")
        self.assertEqual(rule_id, "SD-COMMERCE-001")

        rule_id, _ = rules.match_rule_for_finding("Missing H1 Heading")
        self.assertEqual(rule_id, "ENG-H1-ZERO-001")

        rule_id, _ = rules.match_rule_for_finding("Navigational Dead End")
        self.assertEqual(rule_id, "ENG-NAV-DEADEND-001")

    def test_enrich_finding_attaches_structured_fields(self):
        raw = {
            "title": "Missing JSON-LD Structured Data",
            "severity": "high",
            "evidence": "No application/ld+json block was found.",
            "suggested_action": {"summary": "Add Schema.org JSON-LD.", "priority": "high"},
        }
        context = {"url": "https://brand.test/", "host": "brand.test", "audited_at": "2026-09-07T12:00:00Z", "detector": "schema_detector", "page_role": "homepage"}
        enriched = rules.enrich_finding(raw, context)

        self.assertEqual(enriched["rule_id"], "SD-MISSING-001")
        self.assertIn("root_cause", enriched)
        self.assertIn("expected_mechanism", enriched)
        self.assertEqual(enriched["confidence"], "measured")
        self.assertEqual(enriched["priority_score"], 3.0)  # high (3) * measured (1.0)
        self.assertIn("provenance", enriched)
        self.assertEqual(enriched["provenance"]["source_url"], "https://brand.test/")
        self.assertEqual(enriched["provenance"]["page_role"], "homepage")
        self.assertIn("implementation", enriched)
        self.assertEqual(enriched["implementation"]["label"], "Example snippet only")

    def test_safe_snippet_validates_json_syntax(self):
        context = {"host": "shop.example.com", "url": "https://shop.example.com"}
        snippet = rules.generate_safe_snippet("SD-MISSING-001", "jsonld_org", context)
        self.assertIsNotNone(snippet)
        self.assertEqual(snippet["language"], "json")
        # Extract JSON content from inside <script> tags
        code = snippet["code"]
        json_str = code.split("<script type=\"application/ld+json\">\n")[1].rsplit("\n</script>", 1)[0]
        parsed = json.loads(json_str)
        self.assertEqual(parsed["@type"], "Organization")
        self.assertIn("shop.example.com", parsed["@id"])

    def test_proactive_faq_recommendation(self):
        html_with_qa = "<html><body><h2>Frequently Asked Questions</h2><dt>What is the refund policy?</dt><dd>30 days no questions asked.</dd></body></html>"
        page = {"url": "https://site.test/faq", "html": html_with_qa}
        proactive = rules.generate_proactive_recommendations([page], {"host": "site.test"})
        self.assertTrue(any(p["id"] == "PRO-FAQ-001" for p in proactive))

    def test_proactive_faq_not_triggered_without_qa(self):
        html_normal = "<html><body><h1>Welcome</h1><p>We build great software for enterprises.</p></body></html>"
        page = {"url": "https://site.test/", "html": html_normal}
        proactive = rules.generate_proactive_recommendations([page], {"host": "site.test"})
        self.assertFalse(any(p["id"] == "PRO-FAQ-001" for p in proactive))

    def test_proactive_organization_disambiguation(self):
        html_org_no_sameas = '<script type="application/ld+json">{"@type":"Organization","name":"Acme"}</script>'
        page = {"url": "https://site.test/", "html": html_org_no_sameas}
        proactive = rules.generate_proactive_recommendations([page], {"host": "site.test"})
        self.assertTrue(any(p["id"] == "PRO-ENT-001" for p in proactive))


if __name__ == "__main__":
    unittest.main()
