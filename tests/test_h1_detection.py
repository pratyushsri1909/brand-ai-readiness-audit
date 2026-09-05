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

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("engagement",ROOT/"skills/engagement-audit/scripts/detector.py")
engagement=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(engagement)

class TestH1Detection(unittest.TestCase):
    def audit(self,html): return engagement.audit({"url":"https://site.test/page","html":html})["findings"]
    def test_zero_h1(self): self.assertTrue(any(f["title"]=="Missing H1 Heading" for f in self.audit("<body><p>x</p></body>")))
    def test_one_h1(self): self.assertFalse(any("Multiple H1" in f["title"] or "Missing H1" in f["title"] for f in self.audit("<body><h1>Main</h1></body>")))
    def test_two_h1(self): self.assertTrue(any("Multiple H1" in f["title"] for f in self.audit("<h1>A</h1><h1>B</h1>")))
    def test_three_h1(self): self.assertTrue("3 structural" in next(f["evidence"] for f in self.audit("<h1>A</h1><h1>B</h1><h1>C</h1>") if "Multiple H1" in f["title"]))
    def test_h2_only(self): self.assertTrue(any(f["title"]=="Missing H1 Heading" for f in self.audit("<h2>Sub</h2>")))
    def test_h3_only(self): self.assertTrue(any(f["title"]=="Missing H1 Heading" for f in self.audit("<h3>Sub</h3>")))
    def test_css_class_h1_not_counted(self): self.assertTrue(any(f["title"]=="Missing H1 Heading" for f in self.audit('<div class="h1">Fake</div>')))
    def test_text_h1_not_counted(self): self.assertTrue(any(f["title"]=="Missing H1 Heading" for f in self.audit("<p>h1 is a label</p>")))
    def test_id_h1_not_counted(self): self.assertTrue(any(f["title"]=="Missing H1 Heading" for f in self.audit('<div id="h1">Fake</div>')))
    def test_nested_span_text(self):
        fs=self.audit("<h1><span>Brand</span> Name</h1><h1>Second</h1>")
        self.assertIn("Brand Name", next(f["evidence"] for f in fs if "Multiple H1" in f["title"]))
    def test_nested_div_text(self):
        fs=self.audit("<h1><div>Brand</div> Name</h1><h1>Second</h1>")
        self.assertIn("Brand Name", next(f["evidence"] for f in fs if "Multiple H1" in f["title"]))
    def test_whitespace_h1(self): self.assertFalse(any("Missing H1" in f["title"] for f in self.audit("<h1>  Main   Topic </h1>")))
    def test_h1_case_insensitive(self): self.assertFalse(any("Missing H1" in f["title"] for f in self.audit("<H1>Main</H1>")))
    def test_empty_h1_counts_structurally(self): self.assertFalse(any("Missing H1" in f["title"] for f in self.audit("<h1></h1>")))
    def test_multiple_h1_evidence_names(self):
        fs=self.audit("<h1>First</h1><h1>Second</h1><h1>Third</h1><h1>Fourth</h1>")
        evidence=next(f["evidence"] for f in fs if "Multiple H1" in f["title"])
        self.assertIn("First",evidence); self.assertIn("Third",evidence); self.assertNotIn("Fourth",evidence)
    def test_no_body_no_crash(self): self.assertIsInstance(self.audit(""), list)
