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
from urllib.error import HTTPError

ROOT=Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location("run_audit",ROOT/"skills/audit-orchestrator/scripts/run_audit.py")
run_audit=importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(run_audit)

class MockResponse:
    def __init__(self,text="",status=200,url="https://site.test/page",headers=None):
        self.text=text; self.status=status; self.url=url; self.headers=headers or {}
    def read(self,n=-1): return self.text.encode()
    def getcode(self): return self.status
    def geturl(self): return self.url
    def __enter__(self): return self
    def __exit__(self,*args): return False

class TestOrchestrator(unittest.TestCase):
    def run_with(self,robots,page=None):
        responses=[]
        if isinstance(robots,Exception): responses.append(robots)
        elif isinstance(robots,int): responses.append(HTTPError("https://site.test/robots.txt",robots,"x",{},None))
        else: responses.append(MockResponse(robots,200,"https://site.test/robots.txt"))
        if page is not None: responses.append(page)
        with patch.object(run_audit, "_open_url", side_effect=responses) as mocked:
            result=run_audit.run_pipeline("https://site.test/page")
        return result,mocked

    def test_valid_url(self):
        r,_=self.run_with("User-agent: *\nAllow: /",MockResponse('<html><head><title>T</title></head><body><h1>T</h1><a href="/next">Next</a></body></html>'))
        self.assertEqual(r["site"],"site.test"); self.assertIn("findings",r)
    def test_invalid_scheme(self): self.assertTrue(run_audit.run_pipeline("ftp://site.test")["findings"])
    def test_missing_host(self): self.assertTrue(run_audit.run_pipeline("https://")["findings"])
    def test_robots_disallow(self):
        r,m=self.run_with("User-agent: *\nDisallow: /")
        self.assertEqual(len(m.call_args_list),1); self.assertIn("robots.txt",r["findings"][0]["evidence"])
    def test_robots_allow(self):
        r,m=self.run_with("User-agent: *\nAllow: /",MockResponse("<html><body><h1>x</h1></body></html>"))
        self.assertEqual(len(m.call_args_list),2)
    def test_robots_404_allows(self):
        r,m=self.run_with(404,MockResponse("<html><body><h1>x</h1></body></html>")); self.assertEqual(len(m.call_args_list),2)
    def test_robots_403_blocks(self):
        r,m=self.run_with(403); self.assertEqual(len(m.call_args_list),1); self.assertTrue(r["findings"])
    def test_robots_429_blocks(self):
        r,m=self.run_with(429); self.assertEqual(len(m.call_args_list),1); self.assertEqual(r["summary"]["high"],1)
    def test_robots_500_blocks(self):
        r,m=self.run_with(500); self.assertEqual(len(m.call_args_list),1); self.assertEqual(r["summary"]["high"],1)
    def test_robots_timeout_blocks(self):
        r,m=self.run_with(TimeoutError("timeout")); self.assertEqual(len(m.call_args_list),1)
    def test_robots_network_blocks(self):
        from urllib.error import URLError
        r,m=self.run_with(URLError("dns")); self.assertEqual(len(m.call_args_list),1)
    def test_target_403(self):
        r,m=self.run_with("User-agent: *\nAllow: /",MockResponse("",403)); self.assertEqual(r["findings"][0]["severity"],"high")
    def test_target_404(self):
        r,m=self.run_with("User-agent: *\nAllow: /",MockResponse("",404)); self.assertTrue(r["findings"])
    def test_target_429(self):
        r,m=self.run_with("User-agent: *\nAllow: /",MockResponse("",429)); self.assertTrue(r["findings"])
    def test_target_500(self):
        r,m=self.run_with("User-agent: *\nAllow: /",MockResponse("",500)); self.assertEqual(r["findings"][0]["severity"],"critical")
    def test_target_timeout(self):
        r,m=self.run_with("User-agent: *\nAllow: /",TimeoutError("timeout")); self.assertTrue(r["findings"])
    def test_plain_url_requests(self):
        r,m=self.run_with("User-agent: *\nAllow: /",MockResponse("<html><body><h1>x</h1></body></html>"))
        self.assertEqual(m.call_args_list[0].args[0].full_url,"https://site.test/robots.txt")
        self.assertEqual(m.call_args_list[1].args[0].full_url,"https://site.test/page")
    def test_user_agent(self):
        _,m=self.run_with("User-agent: *\nAllow: /",MockResponse("<h1>x</h1>"))
        self.assertEqual(m.call_args_list[0].args[0].headers["User-agent"],run_audit.USER_AGENT)
    def test_schema_math(self):
        r,_=self.run_with("User-agent: *\nAllow: /",MockResponse("<html><body><h1>x</h1></body></html>"))
        s=r["summary"]; self.assertEqual(s["total_findings"],s["critical"]+s["high"]+s["medium"])
    def test_finding_ids_unique(self):
        html="<html><body>"+"<p>"+"A"*900+"</p>"+"</body></html>"
        r,_=self.run_with("User-agent: *\nAllow: /",MockResponse(html))
        ids=[f["id"] for f in r["findings"]]; self.assertEqual(len(ids),len(set(ids)))
    def test_output_keys(self):
        r,_=self.run_with("User-agent: *\nAllow: /",MockResponse("<html><body><h1>x</h1><a href='/x'>x</a></body></html>"))
        self.assertEqual(set(r),{"site","audited_at","summary","analysis_status","findings"})
    def test_finding_schema(self):
        r,_=self.run_with("User-agent: *\nAllow: /",MockResponse("<html><body><p>x</p></body></html>"))
        for f in r["findings"]: self.assertEqual(set(f),{"id","title","severity","evidence","suggested_action"})
    def test_action_schema(self):
        r,_=self.run_with("User-agent: *\nAllow: /",MockResponse("<html><body><p>x</p></body></html>"))
        for f in r["findings"]: self.assertEqual(set(f["suggested_action"]),{"summary","priority"})

    def test_cross_origin_redirect_checks_target_robots(self):
        responses = [
            MockResponse("User-agent: *\nAllow: /", 200, "https://site.test/robots.txt"),
            MockResponse("", 302, "https://site.test/page", {"Location": "https://other.test/page"}),
            MockResponse("User-agent: *\nDisallow: /", 200, "https://other.test/robots.txt"),
        ]
        with patch.object(run_audit, "_open_url", side_effect=responses) as mocked:
            result = run_audit.run_pipeline("https://site.test/page")
        self.assertEqual(result["site"], "other.test")
        self.assertTrue(any(f["title"] == "Redirect Target Blocked by robots.txt" for f in result["findings"]))
        self.assertEqual(len(mocked.call_args_list), 3)

    def test_cross_origin_redirect_allows_target_and_reports_final_site(self):
        responses = [
            MockResponse("User-agent: *\nAllow: /", 200, "https://site.test/robots.txt"),
            MockResponse("", 302, "https://site.test/page", {"Location": "https://other.test/page"}),
            MockResponse("User-agent: *\nAllow: /", 200, "https://other.test/robots.txt"),
            MockResponse("<html><body><h1>Other</h1></body></html>", 200, "https://other.test/page"),
        ]
        with patch.object(run_audit, "_open_url", side_effect=responses) as mocked:
            result = run_audit.run_pipeline("https://site.test/page")
        self.assertEqual(result["site"], "other.test")
        self.assertEqual(len(mocked.call_args_list), 4)

    def test_rendered_html_optional(self):
        with patch.object(run_audit, "_open_url", side_effect=[MockResponse("User-agent: *\nAllow: /",200,"https://site.test/robots.txt"), MockResponse("<h1>x</h1>",200,"https://site.test/page")]):
            r=run_audit.run_pipeline("https://site.test/page", rendered_html="<p>"+"x"*1000+"</p>")
        self.assertIn("findings",r)
