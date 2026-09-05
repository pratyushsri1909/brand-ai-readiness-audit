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
SPEC = importlib.util.spec_from_file_location("crawl_detector", ROOT / "skills/crawl-render-audit/scripts/detector.py")
crawl = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(crawl)


class TestCrawlRender(unittest.TestCase):
    def _audit(self, html):
        return crawl.audit({"url": "https://site.test/page", "status_code": 200, "headers": {}, "html": html})["findings"]

    def test_status_200(self): self.assertFalse(self._audit("<h1>OK</h1>"))
    def test_status_301_not_error(self): self.assertFalse(crawl.audit({"url":"https://site.test","status_code":301,"headers":{},"html":"x"})["findings"])
    def test_status_400(self): self.assertTrue(crawl.audit({"url":"https://site.test","status_code":400,"headers":{},"html":""})["findings"])
    def test_status_403(self): self.assertEqual(crawl.audit({"url":"https://site.test","status_code":403,"headers":{},"html":""})["findings"][0]["severity"], "high")
    def test_status_404(self): self.assertEqual(crawl.audit({"url":"https://site.test","status_code":404,"headers":{},"html":""})["findings"][0]["severity"], "high")
    def test_status_429(self): self.assertEqual(crawl.audit({"url":"https://site.test","status_code":429,"headers":{},"html":""})["findings"][0]["severity"], "high")
    def test_status_500(self): self.assertEqual(crawl.audit({"url":"https://site.test","status_code":500,"headers":{},"html":""})["findings"][0]["severity"], "critical")
    def test_status_503(self): self.assertEqual(crawl.audit({"url":"https://site.test","status_code":503,"headers":{},"html":""})["findings"][0]["severity"], "critical")
    def test_status_zero(self): self.assertEqual(crawl.audit({"url":"https://site.test","status_code":0,"headers":{},"html":""})["findings"][0]["severity"], "high")
    def test_static_text_no_js_finding(self): self.assertFalse(self._audit("<html><body><h1>" + "A"*600 + "</h1></body></html>"))
    def test_empty_root(self): self.assertTrue(any("Client-Side" in f["title"] for f in self._audit('<div id="root"></div>')))
    def test_empty_app(self): self.assertTrue(any("Client-Side" in f["title"] for f in self._audit('<main id="app"></main>')))
    def test_empty_next(self): self.assertTrue(any("Client-Side" in f["title"] for f in self._audit('<div id="__next"></div>')))
    def test_hydration_low_text(self): self.assertTrue(any("JavaScript-Dependent" in f["title"] for f in self._audit('<script>__NEXT_DATA__</script><script>x()</script>Hi')))
    def test_hydration_with_rich_text_no_finding(self): self.assertFalse(any("JavaScript" in f["title"] for f in self._audit('<script>__NEXT_DATA__</script><script>x()</script>' + 'A'*500)))
    def test_script_heavy_low_text(self): self.assertTrue(any("Script-Heavy" in f["title"] for f in self._audit('<script>' + 'x'*1000 + '</script>' + '<script>' + 'y'*1000 + '</script>' + '<script>' + 'z'*1000 + '</script>' + '<script>' + 'q'*1000 + '</script>tiny')))
    def test_script_heavy_rich_text(self): self.assertFalse(any("Script-Heavy" in f["title"] for f in self._audit('<script>' + 'x'*1000 + '</script>' + '<script>' + 'y'*1000 + '</script>' + '<script>' + 'z'*1000 + '</script>' + '<script>' + 'q'*1000 + '</script>' + 'A'*900)) )
    def test_render_gap_small(self):
        r = crawl.audit({"url":"https://site.test","status_code":200,"headers":{},"html":"A"*100,"rendered_html":"A"*500})
        self.assertFalse(any("Rendered Content" in f["title"] for f in r["findings"]))
    def test_render_gap_large(self):
        r = crawl.audit({"url":"https://site.test","status_code":200,"headers":{},"html":"A"*100,"rendered_html":"A"*700})
        self.assertTrue(any("Rendered Content" in f["title"] for f in r["findings"]))
    def test_script_text_ignored(self): self.assertEqual(crawl.readable_text('<script>SECRET</script><p>Hello</p>'), 'Hello')
    def test_style_text_ignored(self): self.assertEqual(crawl.readable_text('<style>SECRET</style><p>Hello</p>'), 'Hello')
    def test_noscript_text_ignored(self): self.assertEqual(crawl.readable_text('<noscript>SECRET</noscript><p>Hello</p>'), 'Hello')
    def test_template_text_ignored(self): self.assertEqual(crawl.readable_text('<template>SECRET</template><p>Hello</p>'), 'Hello')
    def test_direct_disallow_compat(self):
        fs = crawl.run_crawl_audit("https://site.test/a", 200, "User-agent: *\nDisallow: /a", "<p>x</p>", None)
        self.assertTrue(any(f["title"] == "Content Blocked by robots.txt" for f in fs))
    def test_direct_allow_compat(self):
        fs = crawl.run_crawl_audit("https://site.test/a", 200, "User-agent: *\nAllow: /", "<p>x</p>", None)
        self.assertFalse(any(f["title"] == "Content Blocked by robots.txt" for f in fs))

    def test_meta_noindex_emits_critical(self):
        fs = crawl.audit({"url": "https://site.test", "status_code": 200, "headers": {}, "html": '<meta name="robots" content="noindex, follow">'}).get("findings", [])
        noindex = [f for f in fs if "Noindex Directive" in f["title"]]
        self.assertEqual(len(noindex), 1)
        self.assertEqual(noindex[0]["severity"], "critical")

    def test_header_noindex_emits_critical(self):
        fs = crawl.audit({"url": "https://site.test", "status_code": 200, "headers": {"X-Robots-Tag": "noindex"}, "html": "<p>Content</p>"}).get("findings", [])
        noindex = [f for f in fs if "Noindex Directive" in f["title"]]
        self.assertEqual(len(noindex), 1)
        self.assertEqual(noindex[0]["severity"], "critical")

    def test_meta_nofollow_emits_medium(self):
        fs = crawl.audit({"url": "https://site.test", "status_code": 200, "headers": {}, "html": '<meta name="robots" content="nofollow">'}).get("findings", [])
        nofollow = [f for f in fs if "Nofollow Directive" in f["title"]]
        self.assertEqual(len(nofollow), 1)
        self.assertEqual(nofollow[0]["severity"], "medium")

    def test_conflicting_indexing_directives(self):
        fs = crawl.audit({"url": "https://site.test", "status_code": 200, "headers": {}, "html": '<meta name="robots" content="index, noindex">'}).get("findings", [])
        conflict = [f for f in fs if "Conflicting Indexing Directives" in f["title"]]
        self.assertEqual(len(conflict), 1)
        self.assertEqual(conflict[0]["severity"], "medium")
