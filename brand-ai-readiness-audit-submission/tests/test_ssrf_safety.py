
"""
tests/test_ssrf_safety.py
Tests for SSRF / URL safety validation in run_audit.py.

_is_safe_url does NOT perform DNS lookups (intentionally — DNS rebinding
is ineffective at the HTTP layer). Tests cover scheme, raw-IP, and known
loopback hostname checks only.
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
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "run_audit",
    ROOT / "skills/audit-orchestrator/scripts/run_audit.py",
)
run_audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(run_audit)


class TestIsUrlSafe(unittest.TestCase):
    """Unit tests for _is_safe_url — scheme, raw IP, and hostname checks."""

    # ------- Allowed schemes pass through -------
    def test_public_https_hostname_safe(self):
        with patch.object(run_audit, "_resolve_hostname", return_value=(True, ["93.184.216.34"], "")):
            safe, _, _ = run_audit._is_safe_url("https://example.com/page")
            self.assertTrue(safe)

    def test_public_http_hostname_safe(self):
        with patch.object(run_audit, "_resolve_hostname", return_value=(True, ["93.184.216.34"], "")):
            safe, _, _ = run_audit._is_safe_url("http://example.com/")
            self.assertTrue(safe)

    def test_unknown_tld_hostname_safe(self):
        """Unresolvable TLDs pass through when resolved or allowed."""
        with patch.object(run_audit, "_resolve_hostname", return_value=(True, ["93.184.216.34"], "")):
            safe, _, _ = run_audit._is_safe_url("https://site.test/path", allow_localhost=True)
            self.assertTrue(safe)

    # ------- Dangerous schemes blocked -------
    def test_file_scheme_blocked(self):
        safe, _, reason = run_audit._is_safe_url("file:///etc/passwd")
        self.assertFalse(safe)
        self.assertIn("file", reason.lower())

    def test_ftp_scheme_blocked(self):
        safe, _, reason = run_audit._is_safe_url("ftp://example.com/data")
        self.assertFalse(safe)

    def test_javascript_scheme_blocked(self):
        safe, _, reason = run_audit._is_safe_url("javascript:alert(1)")
        self.assertFalse(safe)

    def test_data_scheme_blocked(self):
        safe, _, reason = run_audit._is_safe_url("data:text/html,<h1>x</h1>")
        self.assertFalse(safe)

    # ------- Loopback hostname blocked -------
    def test_localhost_string_blocked_by_default(self):
        safe, _, reason = run_audit._is_safe_url("http://localhost/admin")
        self.assertFalse(safe)

    def test_localhost_allowed_with_flag(self):
        safe, _, _ = run_audit._is_safe_url("http://localhost/admin", allow_localhost=True)
        self.assertTrue(safe)

    # ------- Raw private IP addresses blocked (no DNS) -------
    def test_raw_loopback_127_blocked(self):
        safe, _, reason = run_audit._is_safe_url("http://127.0.0.1/admin")
        self.assertFalse(safe)
        self.assertIn("127.0.0.1", reason)

    def test_raw_loopback_127_99_blocked(self):
        safe, _, _ = run_audit._is_safe_url("http://127.99.0.1/x")
        self.assertFalse(safe)

    def test_raw_private_10_blocked(self):
        safe, _, _ = run_audit._is_safe_url("http://10.0.0.1/internal")
        self.assertFalse(safe)

    def test_raw_private_172_blocked(self):
        safe, _, _ = run_audit._is_safe_url("http://172.16.0.1/x")
        self.assertFalse(safe)

    def test_raw_private_192_blocked(self):
        safe, _, _ = run_audit._is_safe_url("http://192.168.1.1/router")
        self.assertFalse(safe)

    def test_raw_link_local_blocked(self):
        safe, _, _ = run_audit._is_safe_url("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(safe)

    def test_raw_ipv6_loopback_blocked(self):
        safe, _, _ = run_audit._is_safe_url("http://[::1]/admin")
        self.assertFalse(safe)

    def test_raw_public_ip_safe(self):
        safe, _, _ = run_audit._is_safe_url("http://93.184.216.34/page")
        self.assertTrue(safe)

    # ------- No hostname -------
    def test_no_hostname_blocked(self):
        safe, _, reason = run_audit._is_safe_url("https://")
        self.assertFalse(safe)


class TestPipelineSsrf(unittest.TestCase):
    """Integration tests verifying run_pipeline rejects unsafe URLs before networking."""

    def _no_network(self, req, timeout):
        raise AssertionError(f"Should not make network calls for unsafe URL, got: {req}")

    def test_file_scheme_blocked_no_network_calls(self):
        with patch.object(run_audit, "_open_url", side_effect=self._no_network):
            result = run_audit.run_pipeline("file:///etc/passwd")
        self.assertTrue(result["findings"])

    def test_private_ip_blocked_no_network_calls(self):
        with patch.object(run_audit, "_open_url", side_effect=self._no_network):
            result = run_audit.run_pipeline("http://10.0.0.1/admin")
        self.assertTrue(result["findings"])
        titles = [f["title"] for f in result["findings"]]
        self.assertTrue(any("Blocked" in t or "Invalid" in t for t in titles))

    def test_loopback_ip_blocked_no_network_calls(self):
        with patch.object(run_audit, "_open_url", side_effect=self._no_network):
            result = run_audit.run_pipeline("http://127.0.0.1/admin")
        self.assertTrue(result["findings"])

    def test_localhost_blocked_no_network_calls(self):
        with patch.object(run_audit, "_open_url", side_effect=self._no_network):
            result = run_audit.run_pipeline("http://localhost/admin")
        self.assertTrue(result["findings"])

    def test_allow_localhost_lets_through_to_http_layer(self):
        """_allow_localhost=True skips SSRF block and reaches the HTTP layer (mocked)."""
        from urllib.error import HTTPError

        class FakeResp:
            def read(self, n=-1): return b"<html><body><h1>test</h1></body></html>"
            def getcode(self): return 200
            def geturl(self): return "http://localhost:9000/"
            def __enter__(self): return self
            def __exit__(self, *a): return False
            headers = {}

        robots_err = HTTPError("http://localhost:9000/robots.txt", 404, "Not Found", {}, None)
        page_resp = FakeResp()

        with patch.object(run_audit, "_open_url", side_effect=[robots_err, page_resp]):
            result = run_audit.run_pipeline("http://localhost:9000/", _allow_localhost=True)

        self.assertIn("findings", result)
        self.assertIn("site", result)

    def test_link_local_metadata_endpoint_blocked(self):
        """AWS/GCP instance metadata endpoint blocked without network calls."""
        with patch.object(run_audit, "_open_url", side_effect=self._no_network):
            result = run_audit.run_pipeline("http://169.254.169.254/latest/meta-data/")
        self.assertTrue(result["findings"])


class TestDnsSsrfMocked(unittest.TestCase):
    """Unit and pipeline tests for real DNS resolution SSRF safety with mocks."""

    def setUp(self):
        run_audit._DNS_CACHE.clear()

    def _mock_addrinfo(self, ip_str_list):
        res = []
        for ip_str in ip_str_list:
            family = 2 if ":" not in ip_str else 23  # AF_INET vs AF_INET6
            res.append((family, 1, 6, "", (ip_str, 80)))
        return res

    def test_dns_resolves_to_127_0_0_1_blocked(self):
        with patch("socket.getaddrinfo", return_value=self._mock_addrinfo(["127.0.0.1"])):
            safe, _, reason = run_audit._is_safe_url("http://attacker-controlled.com/admin")
        self.assertFalse(safe)
        self.assertIn("127.0.0.1", reason)

    def test_dns_resolves_to_10_0_0_1_blocked(self):
        with patch("socket.getaddrinfo", return_value=self._mock_addrinfo(["10.0.0.1"])):
            safe, _, reason = run_audit._is_safe_url("http://attacker-controlled.com/admin")
        self.assertFalse(safe)
        self.assertIn("10.0.0.1", reason)

    def test_dns_resolves_to_172_16_blocked(self):
        with patch("socket.getaddrinfo", return_value=self._mock_addrinfo(["172.16.5.10"])):
            safe, _, reason = run_audit._is_safe_url("http://attacker-controlled.com/admin")
        self.assertFalse(safe)
        self.assertIn("172.16.5.10", reason)

    def test_dns_resolves_to_192_168_blocked(self):
        with patch("socket.getaddrinfo", return_value=self._mock_addrinfo(["192.168.1.1"])):
            safe, _, reason = run_audit._is_safe_url("http://attacker-controlled.com/admin")
        self.assertFalse(safe)
        self.assertIn("192.168.1.1", reason)

    def test_dns_resolves_to_169_254_blocked(self):
        with patch("socket.getaddrinfo", return_value=self._mock_addrinfo(["169.254.169.254"])):
            safe, _, reason = run_audit._is_safe_url("http://attacker-controlled.com/admin")
        self.assertFalse(safe)
        self.assertIn("169.254.169.254", reason)

    def test_dns_resolves_to_ipv6_loopback_blocked(self):
        with patch("socket.getaddrinfo", return_value=self._mock_addrinfo(["::1"])):
            safe, _, reason = run_audit._is_safe_url("http://attacker-controlled.com/admin")
        self.assertFalse(safe)
        self.assertIn("::1", reason)

    def test_dns_resolves_to_public_ip_allowed(self):
        with patch("socket.getaddrinfo", return_value=self._mock_addrinfo(["93.184.216.34"])):
            safe, _, reason = run_audit._is_safe_url("http://attacker-controlled.com/page")
        self.assertTrue(safe)
        self.assertEqual(reason, "")

    def test_dns_multiple_records_one_private_blocked(self):
        with patch("socket.getaddrinfo", return_value=self._mock_addrinfo(["93.184.216.34", "10.0.0.1"])):
            safe, _, reason = run_audit._is_safe_url("http://mixed-dns.com/page")
        self.assertFalse(safe)
        self.assertIn("10.0.0.1", reason)

    def test_dns_failure_fails_closed(self):
        import socket
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("Name resolution failed")):
            safe, _, reason = run_audit._is_safe_url("http://unresolvable-domain-xyz123.com/page")
        self.assertFalse(safe)
        self.assertIn("DNS resolution failed", reason)

    def test_unexpected_security_exception_fails_closed(self):
        with patch.object(run_audit, "urlparse", side_effect=RuntimeError("Unexpected parser crash")):
            safe, _, reason = run_audit._is_safe_url("http://example.com/")
        self.assertFalse(safe)
        self.assertEqual(reason, "security_validation_failed")

    def test_redirect_destination_dns_ssrf_blocked_before_fetch(self):
        from urllib.error import HTTPError

        class FakeRedirectResp:
            def __init__(self, target):
                self.headers = {"Location": target}
            def getcode(self): return 302
            def geturl(self): return "https://site.test/jump"
            def __enter__(self): return self
            def __exit__(self, *a): return False

        # When redirected to internal-secret.com, DNS resolves to 10.0.0.5 -> blocked!
        def mock_dns(host, port, *args, **kwargs):
            if "internal-secret" in host:
                return [(2, 1, 6, "", ("10.0.0.5", 80))]
            return [(2, 1, 6, "", ("93.184.216.34", 80))]

        with patch("socket.getaddrinfo", side_effect=mock_dns):
            with patch.object(run_audit, "_open_url", return_value=FakeRedirectResp("http://internal-secret.com/admin")):
                res = run_audit.fetch_page("https://site.test/jump")

        self.assertEqual(res["status_code"], 0)
        self.assertFalse(res.get("redirect_robots_blocked", False))
        self.assertTrue(res.get("redirect_ssrf_blocked", False))
        self.assertEqual(res.get("redirect_scope"), "ssrf_blocked")
        self.assertIn("Redirect to unsafe host blocked", res["error"])


class TestPerAuditDnsCache(unittest.TestCase):
    """Regression tests for per-audit-run DNS cache isolation (Requirement 1)."""

    def test_audit_a_caches_and_audit_b_does_not_reuse(self):
        """Audit A resolves hostname -> cached in A's cache. Audit B starts -> does NOT reuse A's cache."""
        cache_a = run_audit.AuditDnsCache()
        cache_b = run_audit.AuditDnsCache()

        call_counts = {"count": 0}

        def mock_getaddrinfo(host, port, *args, **kwargs):
            call_counts["count"] += 1
            return [(2, 1, 6, "", ("93.184.216.34", 80))]

        with patch("socket.getaddrinfo", side_effect=mock_getaddrinfo):
            # First resolution using Audit A's cache
            ok1, ips1, err1 = run_audit._resolve_hostname("audit-isolation.com", dns_cache=cache_a)
            self.assertTrue(ok1)
            self.assertEqual(call_counts["count"], 1)

            # Second resolution using Audit A's cache should hit cache (no socket call)
            ok2, ips2, err2 = run_audit._resolve_hostname("audit-isolation.com", dns_cache=cache_a)
            self.assertTrue(ok2)
            self.assertEqual(call_counts["count"], 1)
            self.assertIn("audit-isolation.com", cache_a)

            # Audit B starts with its own independent cache -> must NOT reuse Audit A's cache
            self.assertNotIn("audit-isolation.com", cache_b)
            ok3, ips3, err3 = run_audit._resolve_hostname("audit-isolation.com", dns_cache=cache_b)
            self.assertTrue(ok3)
            self.assertEqual(call_counts["count"], 2)  # Re-resolved for Audit B
            self.assertIn("audit-isolation.com", cache_b)

    def test_ttl_expiry_causes_reresolution(self):
        """TTL expiry causes cached entry to be discarded and re-resolved."""
        cache = run_audit.AuditDnsCache(ttl_seconds=0.05)
        call_counts = {"count": 0}

        def mock_getaddrinfo(host, port, *args, **kwargs):
            call_counts["count"] += 1
            return [(2, 1, 6, "", ("93.184.216.34", 80))]

        with patch("socket.getaddrinfo", side_effect=mock_getaddrinfo):
            ok1, _, _ = run_audit._resolve_hostname("ttl-test.com", dns_cache=cache)
            self.assertTrue(ok1)
            self.assertEqual(call_counts["count"], 1)

            # Immediate lookup hits cache
            ok2, _, _ = run_audit._resolve_hostname("ttl-test.com", dns_cache=cache)
            self.assertTrue(ok2)
            self.assertEqual(call_counts["count"], 1)

            # Sleep past TTL
            import time
            time.sleep(0.1)

            # Expired -> causes re-resolution
            ok3, _, _ = run_audit._resolve_hostname("ttl-test.com", dns_cache=cache)
            self.assertTrue(ok3)
            self.assertEqual(call_counts["count"], 2)

    def test_dns_failure_remains_fail_closed(self):
        """DNS failures return fail-closed without caching failed entries as valid IPs."""
        cache = run_audit.AuditDnsCache()
        import socket
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("NXDOMAIN")):
            ok, ips, err = run_audit._resolve_hostname("nonexistent-domain-fail.com", dns_cache=cache)
            self.assertFalse(ok)
            self.assertEqual(ips, [])
            self.assertIn("NXDOMAIN", err)
            # Failed lookup must not be cached as valid
            self.assertNotIn("nonexistent-domain-fail.com", cache)

            # _is_safe_url fails closed
            safe, _, reason = run_audit._is_safe_url("http://nonexistent-domain-fail.com/", dns_cache=cache)
            self.assertFalse(safe)
            self.assertIn("DNS resolution failed", reason)

    def test_ad_hoc_calls_without_cache_do_not_leak_global_state(self):
        """Ad-hoc calls with dns_cache=None resolve without polluting any global state."""
        call_counts = {"count": 0}

        def mock_getaddrinfo(host, port, *args, **kwargs):
            call_counts["count"] += 1
            return [(2, 1, 6, "", ("93.184.216.34", 80))]

        with patch("socket.getaddrinfo", side_effect=mock_getaddrinfo):
            ok1, _, _ = run_audit._resolve_hostname("stateless-test.com", dns_cache=None)
            self.assertTrue(ok1)
            self.assertEqual(call_counts["count"], 1)

            # Second call without cache re-resolves (no process-global cache)
            ok2, _, _ = run_audit._resolve_hostname("stateless-test.com", dns_cache=None)
            self.assertTrue(ok2)
            self.assertEqual(call_counts["count"], 2)


class TestHostInScopeEffectivePort(unittest.TestCase):
    """P0-3: Tests the _host_in_scope function and port boundary checks.
    Regression tests for self-contained, effective-port aware _host_in_scope (Requirement 2).
    """

    def setUp(self):
        import socket
        if hasattr(socket, "_orig_getaddrinfo"):
            self._mocked_getaddrinfo = socket.getaddrinfo
            socket.getaddrinfo = socket._orig_getaddrinfo

    def tearDown(self):
        import socket
        if hasattr(self, "_mocked_getaddrinfo"):
            socket.getaddrinfo = self._mocked_getaddrinfo

    def test_same_host_same_effective_port_allowed(self):
        # Explicit matching ports
        self.assertTrue(run_audit._host_in_scope("example.com:8080", "example.com:8080"))
        self.assertTrue(run_audit._host_in_scope("example.com", "example.com", candidate_port=443, target_port=443))
        self.assertTrue(run_audit._host_in_scope("https://example.com:443", "https://example.com:443"))

    def test_same_host_different_port_rejected(self):
        # Port mismatch must be rejected
        self.assertFalse(run_audit._host_in_scope("example.com:8080", "example.com:443"))
        self.assertFalse(run_audit._host_in_scope("example.com", "example.com", candidate_port=8080, target_port=443))
        self.assertFalse(run_audit._host_in_scope("https://example.com", "example.com:8080"))
        self.assertFalse(run_audit._host_in_scope("http://example.com", "example.com:8080"))

    def test_https_omitted_port_vs_explicit_443_equivalent(self):
        # https:// without port defaults to 443, equivalent to explicit 443
        self.assertTrue(run_audit._host_in_scope("https://example.com", "example.com:443"))
        self.assertTrue(run_audit._host_in_scope("example.com:443", "https://example.com"))
        self.assertTrue(run_audit._host_in_scope("https://example.com", "https://example.com:443"))
        self.assertTrue(run_audit._host_in_scope("example.com", "example.com:443", candidate_scheme="https"))

    def test_http_omitted_port_vs_explicit_80_equivalent(self):
        # http:// without port defaults to 80, equivalent to explicit 80
        self.assertTrue(run_audit._host_in_scope("http://example.com", "example.com:80"))
        self.assertTrue(run_audit._host_in_scope("example.com:80", "http://example.com"))
        self.assertTrue(run_audit._host_in_scope("http://example.com", "http://example.com:80"))
        self.assertTrue(run_audit._host_in_scope("example.com", "example.com:80", candidate_scheme="http"))

    def test_https_443_vs_http_443_handled_by_scheme_policy(self):
        # Mismatched scheme policy: https vs http on port 443 is rejected
        self.assertFalse(run_audit._host_in_scope("https://example.com:443", "http://example.com:443"))
        self.assertFalse(run_audit._host_in_scope("http://example.com:443", "https://example.com:443"))
        self.assertFalse(run_audit._host_in_scope("example.com:443", "example.com:443", candidate_scheme="https", target_scheme="http"))

    def test_subdomain_and_cross_domain_behavior(self):
        # Subdomains of target are allowed
        self.assertTrue(run_audit._host_in_scope("sub.example.com", "example.com"))
        self.assertTrue(run_audit._host_in_scope("deep.sub.example.com", "example.com"))
        self.assertTrue(run_audit._host_in_scope("https://sub.example.com", "https://example.com"))

        # Cross-domain or suffix spoofing must be rejected
        self.assertFalse(run_audit._host_in_scope("other.com", "example.com"))
        self.assertFalse(run_audit._host_in_scope("notexample.com", "example.com"))
        self.assertFalse(run_audit._host_in_scope("example.com", "sub.example.com"))

    def test_empty_or_invalid_host_rejected(self):
        self.assertFalse(run_audit._host_in_scope("", "example.com"))
        self.assertFalse(run_audit._host_in_scope("example.com", ""))
        self.assertFalse(run_audit._host_in_scope(None, "example.com"))

    def test_ssrf_test_domains(self):
        import socket
        _mock = socket.getaddrinfo
        if hasattr(socket, "_real_c_getaddrinfo"):
            socket.getaddrinfo = socket._real_c_getaddrinfo
        try:
            self.assertFalse(run_audit._is_safe_url("http://foo.test")[0])
            self.assertFalse(run_audit._is_safe_url("http://foo.example")[0])
            self.assertFalse(run_audit._is_safe_url("http://foo.invalid")[0])
        finally:
            socket.getaddrinfo = _mock

class TestDnsPinningToctou(unittest.TestCase):
    @unittest.mock.patch("socket.create_connection")
    def test_dns_pinning_toctou(self, mock_create_connection):
        # Prove that validated IP == actual connected IP
        # Simulate _fetch_url where req.pinned_ip is set
        from urllib.request import Request
        import ssl

        # Mock successful connection
        mock_sock = unittest.mock.MagicMock()
        mock_create_connection.return_value = mock_sock

        req = Request("http://example.com/foo")
        req.pinned_ip = "1.2.3.4"
        
        conn = run_audit.PinnedHTTPConnection("example.com", 80)
        conn.pinned_ip = req.pinned_ip
        
        conn.connect()
        mock_create_connection.assert_called_with(("1.2.3.4", 80), conn.timeout, conn.source_address)

        # Test HTTPS
        req = Request("https://example.com/foo")
        req.pinned_ip = "5.6.7.8"
        
        conn = run_audit.PinnedHTTPSConnection("example.com", 443)
        conn.pinned_ip = req.pinned_ip
        
        # Mock ssl wrap_socket
        mock_context = unittest.mock.MagicMock()
        conn._context = mock_context
        
        conn.connect()
        mock_create_connection.assert_called_with(("5.6.7.8", 443), conn.timeout, conn.source_address)
        mock_context.wrap_socket.assert_called_once()
        self.assertEqual(mock_context.wrap_socket.call_args[1]["server_hostname"], "example.com")


if __name__ == "__main__":
    unittest.main()


