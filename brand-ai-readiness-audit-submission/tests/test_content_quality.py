"""
tests/test_content_quality.py
Tests for the content-quality-audit detector.
"""
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
SPEC = importlib.util.spec_from_file_location(
    "cq_detector",
    ROOT / "skills/content-quality-audit/scripts/detector.py",
)
cq = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cq)


def _art(url, body_words, role="general", meta_desc=None, title="Page"):
    """Build a minimal page artifact with controllable content."""
    body = " ".join(["word"] * body_words)
    meta = f'<meta name="description" content="{meta_desc}">' if meta_desc is not None else ""
    html = (
        f"<html><head><title>{title}</title>{meta}</head>"
        f"<body><p>{body}</p></body></html>"
    )
    return {"url": url, "html": html, "page_role": role}


class TestThinContent(unittest.TestCase):
    def _titles(self, findings):
        return [f["title"] for f in findings]

    def test_article_below_threshold_flagged(self):
        art = _art("https://ex.com/blog/a", body_words=50, role="article")
        res = cq.audit(art)
        self.assertIn("Thin Content Detected", self._titles(res["findings"]))

    def test_article_above_threshold_not_flagged(self):
        art = _art("https://ex.com/blog/b", body_words=300, role="article")
        res = cq.audit(art)
        thin = [f for f in res["findings"] if f["title"] == "Thin Content Detected"]
        self.assertEqual(thin, [])

    def test_product_below_threshold_flagged(self):
        art = _art("https://ex.com/p/widget", body_words=30, role="product")
        res = cq.audit(art)
        self.assertIn("Thin Content Detected", self._titles(res["findings"]))

    def test_product_above_threshold_not_flagged(self):
        art = _art("https://ex.com/p/widget", body_words=100, role="product")
        res = cq.audit(art)
        thin = [f for f in res["findings"] if f["title"] == "Thin Content Detected"]
        self.assertEqual(thin, [])

    def test_homepage_very_thin_flagged(self):
        art = _art("https://ex.com/", body_words=10, role="homepage")
        res = cq.audit(art)
        self.assertIn("Thin Content Detected", self._titles(res["findings"]))

    def test_homepage_barely_ok_not_flagged(self):
        art = _art("https://ex.com/", body_words=60, role="homepage")
        res = cq.audit(art)
        thin = [f for f in res["findings"] if f["title"] == "Thin Content Detected"]
        self.assertEqual(thin, [])

    def test_general_role_uses_100_word_threshold(self):
        art = _art("https://ex.com/misc", body_words=50, role="general")
        res = cq.audit(art)
        self.assertIn("Thin Content Detected", self._titles(res["findings"]))


class TestMetaDescription(unittest.TestCase):
    def test_missing_meta_description_flagged(self):
        art = _art("https://ex.com/a", body_words=200, role="general", meta_desc=None)
        res = cq.audit(art)
        titles = [f["title"] for f in res["findings"]]
        self.assertIn("Missing Meta Description", titles)

    def test_present_meta_description_not_flagged(self):
        art = _art("https://ex.com/b", body_words=200, role="general",
                   meta_desc="A great description that is within length.")
        res = cq.audit(art)
        titles = [f["title"] for f in res["findings"]]
        self.assertNotIn("Missing Meta Description", titles)
        self.assertNotIn("Oversized Meta Description", titles)

    def test_oversized_meta_description_flagged(self):
        long_desc = "A" * 321
        art = _art("https://ex.com/c", body_words=200, role="general", meta_desc=long_desc)
        res = cq.audit(art)
        titles = [f["title"] for f in res["findings"]]
        self.assertIn("Oversized Meta Description", titles)


class TestExactDuplicates(unittest.TestCase):
    def _arts(self, url_a, url_b, text_a, text_b):
        def make(url, text):
            return {"url": url, "html": f"<html><body><p>{text}</p></body></html>",
                    "page_role": "general"}
        return {"page_artifacts": [make(url_a, text_a), make(url_b, text_b)]}

    def test_exact_duplicate_detected(self):
        art = self._arts(
            "https://ex.com/a", "https://ex.com/b",
            "This is the same body text repeated exactly word for word across both pages.",
            "This is the same body text repeated exactly word for word across both pages.",
        )
        res = cq.audit(art)
        titles = [f["title"] for f in res["findings"]]
        self.assertIn("Exact Duplicate Content Detected", titles)

    def test_redirected_aliases_to_same_final_url_not_duplicate(self):
        page_a = {
            "url": "https://ex.com/old",
            "requested_url": "https://ex.com/old",
            "final_url": "https://ex.com/current",
            "html": "<html><head><title>Current</title></head><body><p>Identical substantive page content with enough words to be considered meaningful content for duplicate detection.</p></body></html>",
            "page_role": "general",
        }
        page_b = {
            "url": "https://ex.com/current",
            "requested_url": "https://ex.com/current",
            "final_url": "https://ex.com/current",
            "html": page_a["html"],
            "page_role": "general",
        }
        res = cq.audit({"page_artifacts": [page_a, page_b]})
        self.assertFalse(any(f["rule_id"] == "CQ-EXACT-DUP-001" for f in res["findings"]))

    def test_same_template_different_main_content_not_exact_duplicate(self):
        def make(url, title, content):
            html = f"<html><head><title>{title}</title></head><body><header>Shared navigation footer terms</header><main>{content}</main><footer>Shared navigation footer terms</footer></body></html>"
            return {"url": url, "final_url": url, "html": html, "page_role": "article", "title": title}
        pages = [
            make("https://ex.com/a", "Alpha", "Alpha page explains renewable energy storage and grid balancing in detail for operators."),
            make("https://ex.com/b", "Beta", "Beta page explains marine forecasting workflows and ocean observations in detail for researchers."),
        ]
        res = cq.audit({"page_artifacts": pages})
        self.assertFalse(any(f["rule_id"] == "CQ-EXACT-DUP-001" for f in res["findings"]))

    def test_truly_identical_pages_still_detected(self):
        body = "This is genuinely identical substantive content shared exactly across two separate published pages for testing duplicate detection."
        pages = [
            {"url": "https://ex.com/a", "final_url": "https://ex.com/a", "html": f"<html><head><title>Shared</title></head><body><main><p>{body}</p></main></body></html>", "page_role": "general", "title": "Shared"},
            {"url": "https://ex.com/b", "final_url": "https://ex.com/b", "html": f"<html><head><title>Shared</title></head><body><main><p>{body}</p></main></body></html>", "page_role": "general", "title": "Shared"},
        ]
        res = cq.audit({"page_artifacts": pages})
        self.assertTrue(any(f["rule_id"] == "CQ-EXACT-DUP-001" for f in res["findings"]))

    def test_different_pages_not_flagged(self):
        art = self._arts(
            "https://ex.com/a", "https://ex.com/b",
            "The quick brown fox jumps over the lazy dog with great enthusiasm and speed.",
            "An entirely different set of words that shares very little with the first page.",
        )
        res = cq.audit(art)
        titles = [f["title"] for f in res["findings"]]
        self.assertNotIn("Exact Duplicate Content Detected", titles)

    def test_single_page_no_dup_check(self):
        art = {"url": "https://ex.com/a",
               "html": "<html><body><p>Solo page content here.</p></body></html>",
               "page_role": "general"}
        res = cq.audit(art)
        titles = [f["title"] for f in res["findings"]]
        self.assertNotIn("Exact Duplicate Content Detected", titles)


class TestNearDuplicates(unittest.TestCase):
    def _make_page(self, url, text):
        return {"url": url, "html": f"<html><body><p>{text}</p></body></html>",
                "page_role": "article"}

    def test_near_duplicate_detected(self):
        base = "This is a very long piece of text that covers a specific topic in great detail. " * 10
        variant = base[:-5] + "extra words appended to create a slight variation here."
        art = {"page_artifacts": [
            self._make_page("https://ex.com/a", base),
            self._make_page("https://ex.com/b", variant),
        ]}
        res = cq.audit(art)
        titles = [f["title"] for f in res["findings"]]
        self.assertIn("Near-Duplicate Content Detected", titles)

    def test_unrelated_pages_no_near_dup(self):
        text_a = ("Machine learning algorithms process data to identify hidden patterns. " * 5)
        text_b = ("Ancient Roman architecture influenced modern European building design significantly. " * 5)
        art = {"page_artifacts": [
            self._make_page("https://ex.com/ml", text_a),
            self._make_page("https://ex.com/arch", text_b),
        ]}
        res = cq.audit(art)
        titles = [f["title"] for f in res["findings"]]
        self.assertNotIn("Near-Duplicate Content Detected", titles)
        self.assertNotIn("Exact Duplicate Content Detected", titles)


class TestTopicOverlap(unittest.TestCase):
    def _make_page(self, url, text):
        return {"url": url, "html": f"<html><body><p>{text}</p></body></html>",
                "page_role": "article"}

    def test_topic_overlap_detected(self):
        # Two pages using very similar vocabulary about the same topic
        topic = "python programming language tutorial beginner advanced functions classes methods objects"
        text_a = (topic + " ") * 20
        text_b = (topic + " modules libraries packages virtual environments loops conditionals ") * 20
        art = {"page_artifacts": [
            self._make_page("https://ex.com/py1", text_a),
            self._make_page("https://ex.com/py2", text_b),
        ]}
        res = cq.audit(art)
        titles = [f["title"] for f in res["findings"]]
        self.assertIn("Potential Topic Overlap Between Pages", titles)

    def test_no_false_positive_on_different_topics(self):
        text_a = ("gardening plants flowers seeds irrigation outdoor landscape cultivation ") * 15
        text_b = ("cryptocurrency blockchain distributed ledger consensus protocol nodes ") * 15
        art = {"page_artifacts": [
            self._make_page("https://ex.com/garden", text_a),
            self._make_page("https://ex.com/crypto", text_b),
        ]}
        res = cq.audit(art)
        titles = [f["title"] for f in res["findings"]]
        self.assertNotIn("Potential Topic Overlap Between Pages", titles)

    def test_finding_labelled_overlap_not_cannibalization(self):
        """Finding title must never say 'cannibalization'."""
        topic = "content marketing strategy engagement conversion audience brand digital"
        art = {"page_artifacts": [
            self._make_page("https://ex.com/cm1", (topic + " ") * 25),
            self._make_page("https://ex.com/cm2", (topic + " campaign email social ") * 25),
        ]}
        res = cq.audit(art)
        for f in res["findings"]:
            self.assertNotIn("cannibalization", f["title"].lower())
            self.assertNotIn("cannibalization", f.get("evidence", "").lower())


class TestMultiPageMode(unittest.TestCase):
    def test_multi_page_mode_runs_without_error(self):
        artifacts = [
            {"url": f"https://ex.com/page{i}",
             "html": f"<html><head><meta name='description' content='desc'></head><body><p>{'unique ' + str(i) + ' content ' * 50}</p></body></html>",
             "page_role": "article"}
            for i in range(4)
        ]
        res = cq.audit({"page_artifacts": artifacts})
        self.assertIn("findings", res)
        self.assertIsInstance(res["findings"], list)

    def test_findings_have_required_fields(self):
        art = {"url": "https://ex.com/thin",
               "html": "<html><body><p>short</p></body></html>",
               "page_role": "article"}
        res = cq.audit(art)
        for f in res["findings"]:
            self.assertIn("title", f)
            self.assertIn("severity", f)
            self.assertIn("evidence", f)
            self.assertIn("suggested_action", f)
            self.assertIn("summary", f["suggested_action"])

    def test_severity_values_valid(self):
        art = {"url": "https://ex.com/thin",
               "html": "<html><body><p>short</p></body></html>",
               "page_role": "article"}
        res = cq.audit(art)
        valid = {"critical", "high", "medium", "low"}
        for f in res["findings"]:
            self.assertIn(f["severity"], valid)


if __name__ == "__main__":
    unittest.main()
