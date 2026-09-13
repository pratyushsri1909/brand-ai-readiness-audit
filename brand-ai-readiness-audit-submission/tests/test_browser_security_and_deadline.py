"""
tests/test_browser_security_and_deadline.py
Regression tests for:
1. Strict read-only HTTP method enforcement in browser network interception (GET/HEAD allowed, state-changing blocked).
2. Comprehensive Playwright runtime deadline and lifecycle timeout handling.
3. SSRF, scope, and private IP blocking during browser interception.
"""
import importlib.util
import sys
import time
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "run_audit",
    ROOT / "skills/audit-orchestrator/scripts/run_audit.py",
)
run_audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(run_audit)


class TestBrowserSecurityAndDeadline(unittest.TestCase):

    _created_modules = []

    @classmethod
    def setUpClass(cls):
        if "playwright" not in sys.modules:
            mock_pw = types.ModuleType("playwright")
            mock_sync = types.ModuleType("playwright.sync_api")
            mock_sync.sync_playwright = MagicMock()
            mock_pw.sync_api = mock_sync
            sys.modules["playwright"] = mock_pw
            sys.modules["playwright.sync_api"] = mock_sync
            cls._created_modules = ["playwright", "playwright.sync_api"]

    @classmethod
    def tearDownClass(cls):
        for mod in cls._created_modules:
            sys.modules.pop(mod, None)

    def test_deadline_already_exhausted_skips_browser(self):
        """If global deadline is already expired, browser rendering must abort immediately without launching."""
        past_deadline = time.monotonic() - 5.0
        html, avail, reason = run_audit.render_with_browser(
            "https://example.com/",
            target_host="example.com",
            deadline=past_deadline,
        )
        self.assertIsNone(html)
        self.assertFalse(avail)
        self.assertEqual(reason, "browser_safety_rejected: runtime_budget_exhausted")

    def test_remaining_timeout_zero_or_negative_aborts(self):
        """If remaining calculated timeout <= 0, abort cleanly."""
        deadline = time.monotonic()
        html, avail, reason = run_audit.render_with_browser(
            "https://example.com/",
            target_host="example.com",
            deadline=deadline,
            timeout=0,
        )
        self.assertIsNone(html)
        self.assertFalse(avail)
        self.assertEqual(reason, "browser_safety_rejected: runtime_budget_exhausted")

    @patch("playwright.sync_api.sync_playwright")
    def test_browser_launch_failure_handled_gracefully(self, mock_playwright_ctx):
        """Browser launch failure must not crash the audit."""
        mock_p = MagicMock()
        mock_playwright_ctx.return_value.__enter__.return_value = mock_p
        mock_p.chromium.launch.side_effect = RuntimeError("Chromium binary missing or crashed")

        with patch.object(run_audit, "validate_navigation_target", return_value=(True, "")):
            html, avail, reason = run_audit.render_with_browser(
                "https://example.com/",
                target_host="example.com",
                deadline=time.monotonic() + 30.0,
            )
        self.assertIsNone(html)
        self.assertFalse(avail)
        self.assertIn("playwright_launch_failed", reason)

    @patch("playwright.sync_api.sync_playwright")
    def test_page_creation_failure_handled_gracefully(self, mock_playwright_ctx):
        """Page creation failure must close browser and fail gracefully."""
        mock_p = MagicMock()
        mock_browser = MagicMock()
        mock_p.chromium.launch.return_value = mock_browser
        mock_browser.new_page.side_effect = RuntimeError("Context creation failed")
        mock_playwright_ctx.return_value.__enter__.return_value = mock_p

        with patch.object(run_audit, "validate_navigation_target", return_value=(True, "")):
            html, avail, reason = run_audit.render_with_browser(
                "https://example.com/",
                target_host="example.com",
                deadline=time.monotonic() + 30.0,
            )
        self.assertIsNone(html)
        self.assertFalse(avail)
        self.assertIn("playwright_page_creation_failed", reason)
        mock_browser.close.assert_called()

    @patch("playwright.sync_api.sync_playwright")
    def test_page_goto_timeout_handled_gracefully(self, mock_playwright_ctx):
        """page.goto timeout must close browser and report error gracefully."""
        mock_p = MagicMock()
        mock_browser = MagicMock()
        mock_page = MagicMock()
        mock_p.chromium.launch.return_value = mock_browser
        mock_browser.new_page.return_value = mock_page
        mock_page.goto.side_effect = TimeoutError("Navigation timed out")
        mock_playwright_ctx.return_value.__enter__.return_value = mock_p

        with patch.object(run_audit, "validate_navigation_target", return_value=(True, "")):
            html, avail, reason = run_audit.render_with_browser(
                "https://example.com/",
                target_host="example.com",
                deadline=time.monotonic() + 30.0,
            )
        self.assertIsNone(html)
        self.assertFalse(avail)
        self.assertIn("playwright_error: TimeoutError", reason)
        mock_browser.close.assert_called()

    @patch("playwright.sync_api.sync_playwright")
    def test_page_content_failure_handled_gracefully(self, mock_playwright_ctx):
        """page.content() error must close browser and fail gracefully."""
        mock_p = MagicMock()
        mock_browser = MagicMock()
        mock_page = MagicMock()
        mock_p.chromium.launch.return_value = mock_browser
        mock_browser.new_page.return_value = mock_page
        mock_page.content.side_effect = RuntimeError("DOM destroyed")
        mock_playwright_ctx.return_value.__enter__.return_value = mock_p

        with patch.object(run_audit, "validate_navigation_target", return_value=(True, "")):
            html, avail, reason = run_audit.render_with_browser(
                "https://example.com/",
                target_host="example.com",
                deadline=time.monotonic() + 30.0,
            )
        self.assertIsNone(html)
        self.assertFalse(avail)
        self.assertIn("playwright_content_failed", reason)
        mock_browser.close.assert_called()

    @patch("playwright.sync_api.sync_playwright")
    def test_browser_close_exception_does_not_crash(self, mock_playwright_ctx):
        """If browser.close() raises an exception during cleanup, it must not propagate."""
        mock_p = MagicMock()
        mock_browser = MagicMock()
        mock_page = MagicMock()
        mock_p.chromium.launch.return_value = mock_browser
        mock_browser.new_page.return_value = mock_page
        mock_page.content.return_value = "<html><body>Rendered</body></html>"
        mock_browser.close.side_effect = RuntimeError("Browser already dead")
        mock_playwright_ctx.return_value.__enter__.return_value = mock_p

        with patch.object(run_audit, "validate_navigation_target", return_value=(True, "")):
            html, avail, reason = run_audit.render_with_browser(
                "https://example.com/",
                target_host="example.com",
                deadline=time.monotonic() + 30.0,
            )
        self.assertEqual(html, "<html><body>Rendered</body></html>")
        self.assertTrue(avail)
        self.assertIsNone(reason)

    @patch("playwright.sync_api.sync_playwright")
    def test_read_only_method_enforcement_and_scope(self, mock_playwright_ctx):
        """
        Verify handle_request routes:
        - GET / HEAD: permitted if safe and in-scope
        - POST, PUT, PATCH, DELETE, CONNECT, TRACE: aborted unconditionally
        - Out-of-scope or unsafe IP: aborted
        """
        captured_handler = None

        mock_p = MagicMock()
        mock_browser = MagicMock()
        mock_page = MagicMock()
        mock_p.chromium.launch.return_value = mock_browser
        mock_browser.new_page.return_value = mock_page
        mock_page.content.return_value = "<html><body>Rendered</body></html>"

        def capture_route(pattern, handler):
            nonlocal captured_handler
            captured_handler = handler

        mock_page.route.side_effect = capture_route
        mock_playwright_ctx.return_value.__enter__.return_value = mock_p

        with patch.object(run_audit, "validate_navigation_target", return_value=(True, "")):
            html, avail, reason = run_audit.render_with_browser(
                "https://example.com/",
                target_host="example.com",
                deadline=time.monotonic() + 30.0,
            )

        self.assertIsNotNone(captured_handler, "page.route handler must be registered")

        test_cases = [
            ("GET", "https://example.com/api/data", True, "GET to in-scope host must be allowed"),
            ("HEAD", "https://example.com/assets/style.css", True, "HEAD to in-scope host must be allowed"),
            ("POST", "https://example.com/submit-form", False, "POST must be blocked"),
            ("PUT", "https://example.com/resource/1", False, "PUT must be blocked"),
            ("PATCH", "https://example.com/resource/1", False, "PATCH must be blocked"),
            ("DELETE", "https://example.com/resource/1", False, "DELETE must be blocked"),
            ("CONNECT", "https://example.com/tunnel", False, "CONNECT must be blocked"),
            ("TRACE", "https://example.com/", False, "TRACE must be blocked"),
            ("UNKNOWN", "https://example.com/", False, "Non-standard methods must be blocked"),
            ("GET", "https://malicious-external.com/leak", False, "Cross-origin subrequests must be blocked"),
            ("GET", "http://169.254.169.254/latest/meta-data/", False, "Cloud metadata IP must be blocked"),
            ("GET", "http://127.0.0.1:8080/admin", False, "Loopback IP must be blocked"),
            ("GET", "http://192.168.1.1/router", False, "Private IP must be blocked"),
            ("GET", "file:///etc/passwd", False, "File scheme must be blocked"),
            ("GET", "javascript:alert(1)", False, "Javascript scheme must be blocked"),
        ]

        for method, url, should_allow, msg in test_cases:
            mock_route = MagicMock()
            mock_route.request.method = method
            mock_route.request.url = url

            captured_handler(mock_route)

            if should_allow:
                mock_route.continue_.assert_called_once()
                mock_route.abort.assert_not_called()
            else:
                mock_route.abort.assert_called_once()
                mock_route.continue_.assert_not_called()


if __name__ == "__main__":
    unittest.main()
