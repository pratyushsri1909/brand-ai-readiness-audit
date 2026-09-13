import json
import subprocess
import sys
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


from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import threading

ROOT=Path(__file__).resolve().parents[1]
SCRIPT=ROOT/"skills/audit-orchestrator/scripts/run_audit.py"

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/robots.txt":
            body=b"User-agent: *\nAllow: /"
            self.send_response(200); self.send_header("Content-Type","text/plain"); self.end_headers(); self.wfile.write(body); return
        body=b"<html><head><title>Mock</title></head><body><h1>Mock Brand</h1><a href='/next'>Next</a></body></html>"
        self.send_response(200); self.send_header("Content-Type","text/html"); self.end_headers(); self.wfile.write(body)
    def log_message(self,*args): pass

class TestCLIEntrypoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server=HTTPServer(("127.0.0.1",0),Handler); cls.port=cls.server.server_port
        cls.thread=threading.Thread(target=cls.server.serve_forever,daemon=True); cls.thread.start()
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        if hasattr(cls, "thread") and cls.thread.is_alive():
            cls.thread.join(timeout=5)
    def run_cli(self,*args): return subprocess.run([sys.executable,str(SCRIPT),*args],capture_output=True,text=True,timeout=20)
    def test_valid_url_exit_zero(self): self.assertEqual(self.run_cli(f"http://127.0.0.1:{self.port}").returncode,0)
    def test_valid_url_stdout_json(self):
        r=self.run_cli(f"http://127.0.0.1:{self.port}"); data=json.loads(r.stdout); self.assertIn("site",data); self.assertIn("findings",data)
    def test_valid_url_no_nonjson_stdout(self):
        r=self.run_cli(f"http://127.0.0.1:{self.port}"); json.loads(r.stdout); self.assertFalse(r.stdout.lstrip().startswith("Error"))
    def _parse_stderr_json(self, text):
        for line in reversed(text.strip().splitlines()):
            line = line.strip()
            if line.startswith("{") and line.endswith("}"):
                try:
                    return json.loads(line)
                except Exception:
                    continue
        return json.loads(text.strip())

    def test_missing_url_nonzero(self): self.assertNotEqual(self.run_cli().returncode,0)
    def test_missing_url_json_error(self):
        r=self.run_cli(); self.assertEqual(self._parse_stderr_json(r.stderr)["error"],"Missing target URL")
    def test_invalid_scheme_json_error(self):
        r=self.run_cli("ftp://example.com"); self.assertNotEqual(r.returncode,0); self.assertIn("Invalid URL",self._parse_stderr_json(r.stderr)["error"])
