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
SPEC = importlib.util.spec_from_file_location("engagement", ROOT / "skills/engagement-audit/scripts/detector.py")
engagement = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(engagement)


class TestEngagementCTA(unittest.TestCase):
    def audit(self, body_fragment):
        html = "<html><body><h1>Page</h1><a href='/x'>x</a>" + body_fragment + "</body></html>"
        return engagement.audit({"url": "https://site.test/page", "html": html})["findings"]

    def no_cta_finding(self, findings):
        return any(f["title"] == "No Obvious Next Action" for f in findings)

    def test_cta_plain_text_button(self):
        # Visible text with no matching class/id/aria-label must still be recognized.
        findings = self.audit("<button>Buy Now</button>")
        self.assertFalse(self.no_cta_finding(findings))

    def test_cta_plain_text_anchor(self):
        # href has no CTA keyword; only the visible link text does.
        findings = self.audit("<a href='/catalog'>Shop Now</a>")
        self.assertFalse(self.no_cta_finding(findings))

    def test_cta_input_value_attr(self):
        findings = self.audit("<input type='submit' value='Sign Up'>")
        self.assertFalse(self.no_cta_finding(findings))

    def test_cta_attr_based_still_works(self):
        # Regression guard: the original attribute/class-based path must keep working.
        findings = self.audit("<button class='buy-btn'>Purchase</button>")
        self.assertFalse(self.no_cta_finding(findings))

    def test_no_cta_at_all(self):
        findings = self.audit("<p>Just some unrelated paragraph text here.</p>")
        self.assertTrue(self.no_cta_finding(findings))

    def test_cta_false_positive_guard(self):
        # None of these contain a genuine CTA; they must NOT be misread as one
        # merely because a keyword appears as a substring of an ordinary word.
        for label in ("Cartoons for kids", "Bookshelf", "Startup Stories", "Shopify Integration Docs"):
            with self.subTest(label=label):
                findings = self.audit(f"<a href='/x2'>{label}</a>")
                self.assertTrue(self.no_cta_finding(findings), f"{label!r} was incorrectly treated as a CTA")

    def test_cta_case_insensitive(self):
        findings = self.audit("<button>BUY NOW</button>")
        self.assertFalse(self.no_cta_finding(findings))

    def test_multiple_ctas(self):
        findings = self.audit("<button>Buy Now</button><a href='/contact'>Learn More</a>")
        self.assertFalse(self.no_cta_finding(findings))

    def test_relative_link_no_leading_slash_prevents_dead_end(self):
        findings = self.audit("<a href='about.html'>About Us</a><button>Buy Now</button>")
        self.assertFalse(any("Navigational Dead End" in f["title"] for f in findings))

    def test_relative_parent_link_prevents_dead_end(self):
        findings = self.audit("<a href='../pricing'>Pricing Plans</a><button>Buy Now</button>")
        self.assertFalse(any("Navigational Dead End" in f["title"] for f in findings))


if __name__ == "__main__":
    unittest.main()
