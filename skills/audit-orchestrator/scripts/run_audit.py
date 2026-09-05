import concurrent.futures
import contextlib
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
import re
import socket
import sys
import threading
import time
from datetime import datetime, timezone
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener
import urllib.robotparser

USER_AGENT = "BrandAIAuditBot/1.0"
ROBOTS_TIMEOUT = 5
PAGE_TIMEOUT = 10
MAX_RESPONSE_SIZE = 5 * 1024 * 1024
MAX_REDIRECTS = 5
DEFAULT_MAX_PAGES = 20
HARD_MAX_PAGES = 50
MAX_DEPTH = 3
MAX_SITEMAPS = 10
MAX_SITEMAP_DEPTH = 3
MAX_SITEMAP_URLS = 100
MAX_SITEMAP_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_BROWSER_PAGES = 3
CIRCUIT_BREAKER_THRESHOLD = 3
DEFAULT_GLOBAL_TIMEOUT = 240.0  # 240s wall-clock crawl deadline (<5m)
MAX_RETRIES = 1
POLITENESS_DELAY_SECONDS = 0.05

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))


def _load_detector(name, relative_path):
    path = os.path.join(ROOT, relative_path)
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to load {relative_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


crawl_detector = _load_detector("crawl_detector", "skills/crawl-render-audit/scripts/detector.py")
schema_detector = _load_detector("schema_detector", "skills/structured-data-freshness/scripts/detector.py")
engagement_detector = _load_detector("engagement_detector", "skills/engagement-audit/scripts/detector.py")
discovery_detector = _load_detector("discovery_detector", "skills/site-discovery-audit/scripts/detector.py")
entity_detector = _load_detector("entity_detector", "skills/entity-corroboration-audit/scripts/detector.py")
content_quality_detector = _load_detector("content_quality_detector", "skills/content-quality-audit/scripts/detector.py")
rules_module = _load_detector("rules_module", "skills/audit-orchestrator/scripts/rules.py")


import http.client

def _read_limited(response, max_bytes=MAX_RESPONSE_SIZE):
    try:
        return response.read(max_bytes).decode("utf-8", errors="replace")
    except http.client.IncompleteRead as e:
        return e.partial.decode("utf-8", errors="replace")


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

import socket
import ssl
from http.client import HTTPConnection, HTTPSConnection
from urllib.request import HTTPHandler, HTTPSHandler

class PinnedHTTPConnection(HTTPConnection):
    def connect(self):
        pinned_ip = getattr(self, "pinned_ip", None)
        host = pinned_ip if pinned_ip else self.host
        self.sock = socket.create_connection((host, self.port), self.timeout, self.source_address)

class PinnedHTTPSConnection(HTTPSConnection):
    def connect(self):
        pinned_ip = getattr(self, "pinned_ip", None)
        host = pinned_ip if pinned_ip else self.host
        sock = socket.create_connection((host, self.port), self.timeout, self.source_address)
        
        server_hostname = self.host
        if server_hostname.startswith('[') and server_hostname.endswith(']'):
            server_hostname = server_hostname[1:-1]
            
        if getattr(self, "_context", None):
            self.sock = self._context.wrap_socket(sock, server_hostname=server_hostname)
        else:
            context = ssl.create_default_context()
            self.sock = context.wrap_socket(sock, server_hostname=server_hostname)

class PinnedHTTPHandler(HTTPHandler):
    def http_open(self, req):
        def _conn_factory(*args, **kwargs):
            conn = PinnedHTTPConnection(*args, **kwargs)
            conn.pinned_ip = getattr(req, "pinned_ip", None)
            return conn
        return self.do_open(_conn_factory, req)

class PinnedHTTPSHandler(HTTPSHandler):
    def https_open(self, req):
        def _conn_factory(*args, **kwargs):
            if hasattr(self, "_context"):
                kwargs["context"] = self._context
            if hasattr(self, "_check_hostname"):
                kwargs["check_hostname"] = self._check_hostname
            conn = PinnedHTTPSConnection(*args, **kwargs)
            conn.pinned_ip = getattr(req, "pinned_ip", None)
            return conn
        return self.do_open(_conn_factory, req)

_NO_REDIRECT_OPENER = build_opener(_NoRedirectHandler, PinnedHTTPHandler, PinnedHTTPSHandler)

def _open_url(request, timeout):
    return _NO_REDIRECT_OPENER.open(request, timeout=timeout)


# ---------------------------------------------------------------------------
# SSRF safety: block private/internal/loopback hosts, DNS resolution checks
# ---------------------------------------------------------------------------
_SAFE_SCHEMES = {"http", "https"}
_TEST_BYPASS_HOSTS = {"localhost", "127.0.0.1", "::1"}

_BLOCKED_HOSTNAMES = frozenset({
    "localhost", "ip6-localhost", "ip6-loopback",
    "broadcasthost",
})


class AuditDnsCache:
    """Per-audit-run DNS cache with bounded TTL (Requirement 5)."""
    def __init__(self, ttl_seconds=30.0):
        self.ttl = ttl_seconds
        self.entries = {}  # hostname -> (timestamp, result)

    def get(self, hostname, default=None):
        entry = self.entries.get(hostname)
        if entry:
            ts, res = entry
            if time.monotonic() - ts <= self.ttl:
                return res
            del self.entries[hostname]
        return default

    def set(self, hostname, result):
        self.entries[hostname] = (time.monotonic(), result)

    def clear(self):
        self.entries.clear()

    def __contains__(self, hostname):
        return self.get(hostname) is not None

    def __getitem__(self, hostname):
        val = self.get(hostname)
        if val is None:
            raise KeyError(hostname)
        return val

    def __setitem__(self, hostname, result):
        self.set(hostname, result)


class _ModuleDnsCacheStub:
    """Non-caching stub for backward-compatibility with external callers referencing _DNS_CACHE."""
    def clear(self): pass
    def get(self, *args, **kwargs): return None
    def set(self, *args, **kwargs): pass
    def __contains__(self, k): return False


_DNS_CACHE = _ModuleDnsCacheStub()


def _is_safe_ip_obj(ip):
    """
    Checks if an ipaddress object is a public globally routable address.
    Rejects: loopback, link_local, private (RFC1918), reserved, multicast, unspecified, non-global.
    Handles IPv4-mapped IPv6 addresses (Requirement 4).
    """
    if getattr(ip, "ipv4_mapped", None):
        return _is_safe_ip_obj(ip.ipv4_mapped)
    if ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return False
    if not ip.is_global:
        return False
    return True


def _parse_ip_or_alternate(hostname):
    """
    Attempts to parse hostname as IPv4/IPv6, including alternate forms (Requirement 4):
    - standard dotted decimal (127.0.0.1)
    - integer decimal (2130706433)
    - hex (0x7f000001 or 0x7f.0.0.1)
    - octal (0177.0.0.1)
    - IPv6 and IPv4-mapped IPv6 (::ffff:127.0.0.1)
    Returns an ipaddress.IPv4Address or IPv6Address, or None.
    """
    if not hostname:
        return None
    hostname_clean = hostname.strip().strip("[]").lower()
    try:
        return ipaddress.ip_address(hostname_clean)
    except ValueError:
        pass

    # Integer decimal representation (e.g. 2130706433 -> 127.0.0.1)
    if re.fullmatch(r"\d+", hostname_clean):
        try:
            val = int(hostname_clean)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except (ValueError, OverflowError):
            pass

    # Single hex integer (e.g. 0x7f000001)
    if re.fullmatch(r"0x[0-9a-fA-F]+", hostname_clean):
        try:
            val = int(hostname_clean, 16)
            if 0 <= val <= 0xFFFFFFFF:
                return ipaddress.IPv4Address(val)
        except (ValueError, OverflowError):
            pass

    # Dotted hex or octal parts (e.g. 0x7f.0.0.1 or 0177.0.0.1)
    parts = hostname_clean.split(".")
    if len(parts) == 4:
        try:
            parsed_octets = []
            for p in parts:
                if p.startswith("0x") or p.startswith("0X"):
                    val = int(p, 16)
                elif p.startswith("0") and len(p) > 1 and p.isdigit():
                    val = int(p, 8)
                else:
                    val = int(p)
                if not (0 <= val <= 255):
                    return None
                parsed_octets.append(str(val))
            return ipaddress.IPv4Address(".".join(parsed_octets))
        except (ValueError, OverflowError):
            pass

    # IPv4-mapped IPv6 (e.g. ::ffff:127.0.0.1 or ::ffff:7f00:1)
    try:
        addr = ipaddress.IPv6Address(hostname_clean)
        if addr.ipv4_mapped:
            return addr.ipv4_mapped
        return addr
    except ValueError:
        pass

    return None


def _is_safe_ip(ip_str):
    ip = _parse_ip_or_alternate(ip_str)
    if ip is not None:
        return _is_safe_ip_obj(ip)
    return False


def _resolve_hostname(hostname, timeout=2.0, deadline=None, dns_cache=None):
    """
    Resolve a hostname to A/AAAA addresses with a bounded wait and per-audit cache.
    """
    hostname = (hostname or "").strip().lower().rstrip(".")
    if not hostname:
        return False, [], "dns_resolution_failed: empty hostname"

    if dns_cache is not None:
        cached = dns_cache.get(hostname)
        if cached is not None:
            return cached

    if deadline is not None and time.monotonic() >= deadline:
        return False, [], "runtime_budget_exhausted"

    result_holder = []
    error_holder = []

    def resolve():
        try:
            results = socket.getaddrinfo(
                hostname,
                None,
                socket.AF_UNSPEC,
                socket.SOCK_STREAM,
            )
            ips = []
            for res in results:
                sockaddr = res[4]
                if sockaddr:
                    ip_str = sockaddr[0]
                    if ip_str not in ips:
                        ips.append(ip_str)
            result_holder.append(
                (True, ips, "") if ips
                else (False, [], f"No IP addresses returned for {hostname}")
            )
        except (socket.gaierror, socket.herror, OSError) as exc:
            error_holder.append(f"dns_resolution_failed: {exc}")
        except Exception as exc:
            error_holder.append(
                f"dns_validation_failed: {type(exc).__name__}: {exc}"
            )

    worker = threading.Thread(
        target=resolve,
        name="brand-ai-dns",
        daemon=True,
    )
    worker.start()

    wait_timeout = max(0.0, float(timeout))
    if deadline is not None:
        wait_timeout = min(
            wait_timeout,
            max(0.0, deadline - time.monotonic()),
        )

    worker.join(wait_timeout)

    if worker.is_alive():
        return False, [], (
            f"dns_resolution_failed: DNS resolution timed out after {wait_timeout:.2f}s"
        )

    if result_holder:
        result = result_holder[0]
        if result[0] and dns_cache is not None:
            dns_cache.set(hostname, result)
        return result

    if error_holder:
        return False, [], error_holder[0]

    return False, [], "dns_resolution_failed: resolver returned no result"


def _is_safe_url(url, allow_localhost=False, deadline=None, dns_timeout=2.0, dns_cache=None):
    """
    Returns (is_safe: bool, validated_ip: str, reason: str).
    Blocks:
      - Non-HTTP(S) schemes (file, ftp, javascript, data, etc.)
      - Raw private/loopback/link-local/reserved IP addresses (including hex, octal, decimal int, IPv4-mapped IPv6)
      - Loopback hostnames (localhost etc.) unless allow_localhost=True
      - Hostnames resolving to private/internal/non-global IP ranges via DNS A/AAAA
    Fails closed on any DNS failure or unexpected exception.
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in _SAFE_SCHEMES:
            return False, None, f"Unsupported or dangerous URL scheme: {parsed.scheme!r}"
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            return False, None, "URL has no resolvable hostname"

        if allow_localhost and hostname in _TEST_BYPASS_HOSTS:
            return True, None, ""

        direct_ip = _parse_ip_or_alternate(hostname)
        if direct_ip is not None:
            if not _is_safe_ip_obj(direct_ip):
                return False, None, f"Raw IP address {parsed.hostname!r} is in a private/reserved range"
            return True, None, ""

        if hostname in _BLOCKED_HOSTNAMES:
            return False, None, f"Loopback hostname {parsed.hostname!r} is not permitted"

        ok, ip_list, err = _resolve_hostname(hostname, timeout=dns_timeout, deadline=deadline, dns_cache=dns_cache)
        if not ok:
            if err == "runtime_budget_exhausted":
                return False, None, "runtime_budget_exhausted"
            return False, None, f"DNS resolution failed: {err}"
        if not ip_list:
            return False, None, f"DNS returned no addresses for {hostname!r}"

        safe_ip = None
        for ip_str in ip_list:
            ip = _parse_ip_or_alternate(ip_str)
            if ip is None or not _is_safe_ip_obj(ip):
                return False, None, f"Hostname {hostname!r} resolved to private/reserved IP: {ip_str}"
            if safe_ip is None:
                safe_ip = ip_str

        return True, safe_ip, ""
    except Exception:
        return False, None, "security_validation_failed"


# ---------------------------------------------------------------------------
# Centralized Navigation / Fetching Safety Policy
# ---------------------------------------------------------------------------
_COMMON_MULTI_LABEL_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.in", "firm.in", "net.in", "org.in", "gen.in", "ind.in",
    "co.jp", "co.nz", "com.br", "com.cn", "com.sg", "com.tr",
})


def _registrable_domain(hostname):
    """Return a conservative registrable-domain approximation without network access."""
    host = (hostname or "").lower().rstrip(".").strip("[]")
    if not host:
        return ""
    # IP literals are their own scope domain.
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = [p for p in host.split(".") if p]
    if len(labels) <= 2:
        return host
    suffix2 = ".".join(labels[-2:])
    if suffix2 in _COMMON_MULTI_LABEL_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _host_in_scope(candidate_host, target_host, candidate_port=None, target_port=None,
                   candidate_scheme=None, target_scheme=None, allow_subdomains=True):
    """Self-contained, port- and scheme-aware host scope predicate.

    The audit owns one hostname and its descendants. Generic ``www.`` is normalized
    to the registrable-looking base host, while a parent of a more specific target
    is never admitted. This preserves the existing least-privilege crawl boundary.
    """
    def _split_host_port(value):
        value = str(value or "").strip()
        scheme = None
        port = None
        if "://" in value:
            parsed = urlparse(value)
            scheme = parsed.scheme.lower() or None
            host = parsed.hostname or ""
            port = parsed.port
            return host.lower().rstrip("."), port, scheme
        # URL-like netloc without scheme (including IPv6 literals).
        parsed = urlparse("//" + value)
        host = parsed.hostname or value.strip("[]")
        port = parsed.port
        return host.lower().rstrip("."), port, scheme

    candidate, parsed_cand_port, parsed_cand_scheme = _split_host_port(candidate_host)
    target, parsed_target_port, parsed_target_scheme = _split_host_port(target_host)
    if candidate_port is None:
        candidate_port = parsed_cand_port
    if target_port is None:
        target_port = parsed_target_port
    if not candidate_scheme:
        candidate_scheme = parsed_cand_scheme
    if not target_scheme:
        target_scheme = parsed_target_scheme

    if not candidate or not target:
        return False

    target_base = target[4:] if target.startswith("www.") else target
    host_match = candidate == target_base or (
        allow_subdomains and candidate.endswith("." + target_base)
    )
    if not host_match:
        return False

    cand_eff_port = candidate_port
    if cand_eff_port is None and candidate_scheme:
        cand_eff_port = 443 if candidate_scheme == "https" else 80 if candidate_scheme == "http" else None
    targ_eff_port = target_port
    if targ_eff_port is None and target_scheme:
        targ_eff_port = 443 if target_scheme == "https" else 80 if target_scheme == "http" else None

    if cand_eff_port is not None and targ_eff_port is not None:
        if int(cand_eff_port) != int(targ_eff_port):
            return False
    if candidate_scheme and target_scheme and candidate_scheme != target_scheme:
        return False
    return True


def validate_navigation_target(url, target_host=None, robots_cache=None, allow_localhost=False, deadline=None, target_port=None, dns_cache=None):
    """
    Centralized safety policy for HTTP fetches and browser navigation.

    Validation order is deliberate:
      1. deadline (Requirement 7)
      2. URL syntax / scheme
      3. obvious crawl-scope rejection (port-aware, Requirement 4)
      4. SSRF / DNS safety
      5. robots.txt
    """
    if deadline is not None and time.monotonic() >= deadline:
        return False, "runtime_budget_exhausted"

    if not url or not isinstance(url, str):
        return False, "empty_or_invalid_url"

    try:
        parsed = urlparse(url)
    except Exception as exc:
        return False, f"invalid_url: {exc}"

    if parsed.scheme not in _SAFE_SCHEMES:
        return False, f"unsupported_scheme: {parsed.scheme}"
    if not parsed.netloc:
        return False, "missing_hostname"

    url_host_clean = (parsed.hostname or "").lower().rstrip(".")
    cand_port = parsed.port or (443 if parsed.scheme == "https" else 80)

    if target_host is not None:
        if ":" in target_host and not target_host.startswith("["):
            th, tp = target_host.rsplit(":", 1)
            target_host_clean = th.lower().rstrip(".")
            try:
                t_port = int(tp)
            except ValueError:
                t_port = target_port
        else:
            target_host_clean = (target_host or "").lower().rstrip(".")
            t_port = target_port

        if not _host_in_scope(url_host_clean, target_host_clean, candidate_port=cand_port, target_port=t_port, candidate_scheme=parsed.scheme):
            return False, f"out_of_scope: host {url_host_clean}:{cand_port} != {target_host_clean}:{t_port}"

    safe, validated_ip, ssrf_reason = _is_safe_url(
        url,
        allow_localhost=allow_localhost,
        deadline=deadline,
        dns_cache=dns_cache,
    )
    if not safe:
        if ssrf_reason == "runtime_budget_exhausted":
            return False, "runtime_budget_exhausted"
        return False, f"ssrf_rejected: {ssrf_reason}"

    if robots_cache is not None:
        robots_result = robots_cache.get_robots(
            parsed,
            allow_localhost=allow_localhost,
            deadline=deadline,
        )
        if not robots_cache.allows(url, robots_result=robots_result):
            reason = robots_result.get(
                "error",
                robots_result.get("status", "disallowed"),
            )
            return False, f"robots_blocked: {reason}"

    return True, ""


# ---------------------------------------------------------------------------
# Robots & Origin Cache
# ---------------------------------------------------------------------------
class RobotsCache:
    """Per-origin cached robots.txt policy manager."""
    def __init__(self):
        self._cache = {}

    def get_robots(self, parsed, allow_localhost=False, deadline=None):
        origin = (parsed.scheme.lower(), parsed.netloc.lower())
        if origin in self._cache:
            return self._cache[origin]

        orig_scheme, orig_netloc = origin
        robots_url = f"{orig_scheme}://{orig_netloc}/robots.txt"

        if deadline is not None and time.monotonic() >= deadline:
            return {"status": "unsafe", "content": "", "url": robots_url, "error": "runtime_budget_exhausted"}

        op_timeout = _deadline_timeout(ROBOTS_TIMEOUT, deadline=deadline)
        if op_timeout <= 0.0:
            return {"status": "unsafe", "content": "", "url": robots_url, "error": "runtime_budget_exhausted"}

        current_url = robots_url
        for redirects in range(MAX_REDIRECTS):
            if deadline is not None and time.monotonic() >= deadline:
                result = {"status": "unsafe", "content": "", "url": current_url, "error": "runtime_budget_exhausted"}
                break
            op_timeout = _deadline_timeout(ROBOTS_TIMEOUT, deadline=deadline)
            if op_timeout <= 0.0:
                result = {"status": "unsafe", "content": "", "url": current_url, "error": "runtime_budget_exhausted"}
                break

            safe, validated_ip, reason = _is_safe_url(current_url, allow_localhost=allow_localhost, deadline=deadline)
            if not safe:
                result = {"status": "unsafe", "content": "", "url": current_url, "error": f"ssrf_rejected: {reason}"}
                break

            request = Request(current_url, headers={"User-Agent": USER_AGENT})
            if validated_ip:
                request.pinned_ip = validated_ip
            try:
                with _open_url(request, op_timeout) as response:
                    result = {"status": "ok", "content": _read_limited(response), "url": current_url}
                    break
            except HTTPError as exc:
                if exc.code in (301, 302, 303, 307, 308):
                    new_url = exc.headers.get("Location")
                    if not new_url:
                        result = {"status": "unsafe", "content": "", "url": current_url, "error": "redirect_missing_location"}
                        break
                    new_url = urljoin(current_url, new_url)
                    parsed_new = urlparse(new_url)
                    if parsed_new.scheme not in _SAFE_SCHEMES:
                        result = {"status": "unsafe", "content": "", "url": current_url, "error": "redirect_unsafe_scheme"}
                        break
                    safe, validated_ip, reason = _is_safe_url(new_url, allow_localhost=allow_localhost, deadline=deadline)
                    if not safe:
                        result = {"status": "unsafe", "content": "", "url": current_url, "error": f"redirect_unsafe_target: {reason}"}
                        break
                    if not _host_in_scope(parsed_new.netloc, orig_netloc, candidate_scheme=parsed_new.scheme):
                        result = {"status": "unsafe", "content": "", "url": current_url, "error": "redirect_out_of_scope"}
                        break
                    current_url = new_url
                elif exc.code == 404:
                    result = {"status": "absent", "content": "", "url": current_url}
                    break
                elif exc.code in (401, 403, 429) or exc.code >= 500:
                    result = {"status": "unsafe", "content": "", "url": current_url, "error": f"HTTP {exc.code}"}
                    break
                else:
                    result = {"status": "unknown", "content": "", "url": current_url, "error": f"HTTP {exc.code}"}
                    break
            except (URLError, TimeoutError, OSError) as exc:
                result = {"status": "unsafe", "content": "", "url": current_url, "error": str(exc)}
                break
        else:
            result = {"status": "unsafe", "content": "", "url": current_url, "error": "redirect_loop"}

        self._cache[origin] = result
        return result

    def allows(self, target_url, parsed=None, robots_result=None, allow_localhost=False, deadline=None):
        if robots_result is None:
            if parsed is None:
                parsed = urlparse(target_url)
            robots_result = self.get_robots(parsed, allow_localhost=allow_localhost, deadline=deadline)
        if not robots_result or not isinstance(robots_result, dict):
            return False
        status = robots_result.get("status")
        if status == "absent":
            return True
        if status != "ok":
            return False
        parser = urllib.robotparser.RobotFileParser()
        parser.parse(robots_result.get("content", "").splitlines())
        return parser.can_fetch(USER_AGENT, target_url)


def fetch_robots(parsed):
    cache = RobotsCache()
    return cache.get_robots(parsed)


def robots_allows(target_url, robots_result):
    if not robots_result or not isinstance(robots_result, dict):
        return False
    status = robots_result.get("status")
    if status == "absent":
        return True
    if status != "ok":
        return False
    parser = urllib.robotparser.RobotFileParser()
    parser.parse(robots_result.get("content", "").splitlines())
    return parser.can_fetch(USER_AGENT, target_url)


# ---------------------------------------------------------------------------
# Adaptive Politeness & Bounded HTTP Fetching
# ---------------------------------------------------------------------------
class OriginThrottler:
    """Lightweight adaptive per-origin politeness and backoff tracker (Requirement 8)."""
    def __init__(self, base_delay=POLITENESS_DELAY_SECONDS, max_delay=1.0):
        self.base_delay = base_delay
        self.max_delay = max_delay
        self._states = {}  # origin -> {"delay": base_delay, "last_fetch": 0.0, "errors": 0}

    def wait(self, origin, deadline=None):
        now = time.monotonic()
        st = self._states.setdefault(origin, {"delay": self.base_delay, "last_fetch": 0.0, "errors": 0})
        elapsed = now - st["last_fetch"]
        cur_delay = st["delay"]
        if 0 <= elapsed < cur_delay:
            _deadline_sleep(cur_delay - elapsed, deadline=deadline)
        st["last_fetch"] = time.monotonic()

    def record_outcome(self, origin, status_code=200, latency=0.0, is_error=False):
        st = self._states.setdefault(origin, {"delay": self.base_delay, "last_fetch": 0.0, "errors": 0})
        if status_code in (429, 500, 502, 503, 504) or is_error or latency > 2.0:
            st["errors"] += 1
            st["delay"] = min(self.max_delay, max(self.base_delay, st["delay"] * 1.5 + 0.05))




_DEFAULT_THROTTLER = OriginThrottler()


def _deadline_timeout(configured_timeout, deadline=None):
    """Calculates effective operation timeout under global deadline (Requirement 7)."""
    if deadline is None:
        return max(0.0, float(configured_timeout))
    remaining = deadline - time.monotonic()
    if remaining <= 0.0:
        return 0.0
    return min(max(0.0, float(configured_timeout)), remaining)


def _deadline_sleep(delay, deadline=None):
    if delay <= 0:
        return True
    if deadline is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        sleep_time = min(delay, remaining)
        if sleep_time > 0:
            time.sleep(sleep_time)
        return time.monotonic() < deadline
    else:
        time.sleep(delay)
        return True


def _apply_politeness(origin, deadline=None, throttler=None):
    (throttler or _DEFAULT_THROTTLER).wait(origin, deadline=deadline)


def fetch_page(url, initial_robots=None, allow_localhost=False, robots_cache=None, deadline=None,
               max_retries=MAX_RETRIES, target_host=None, max_response_bytes=MAX_RESPONSE_SIZE, dns_cache=None, throttler=None):
    """
    Performs bounded HTTP fetch with manual redirect tracking, SSRF safety,
    per-origin robots re-evaluation, transient retry policy, cross-origin redirect
    pre-fetch boundary checks, and stream-level response size capping.
    """
    if robots_cache is None:
        robots_cache = RobotsCache()
        if initial_robots:
            parsed_initial = urlparse(url)
            robots_cache._cache[(parsed_initial.scheme.lower(), parsed_initial.netloc.lower())] = initial_robots

    current_url = url
    redirects = 0
    redirect_chain = []
    robots_result = initial_robots
    total_retries = 0

    while True:
        if deadline is not None and time.monotonic() >= deadline:
            return {
                "status_code": 0, "final_url": current_url, "headers": {}, "raw_html": "",
                "error": "runtime_budget_exhausted",
                "redirect_robots_blocked": False, "redirect_chain": redirect_chain,
                "redirect_scope": "none", "retries": total_retries,
            }

        safe, validated_ip, reason = _is_safe_url(current_url, allow_localhost=allow_localhost, deadline=deadline, dns_cache=dns_cache)
        if not safe:
            if reason == "runtime_budget_exhausted":
                return {
                    "status_code": 0, "final_url": current_url, "headers": {}, "raw_html": "",
                    "error": "runtime_budget_exhausted",
                    "redirect_robots_blocked": False, "redirect_chain": redirect_chain,
                    "redirect_scope": "none", "retries": total_retries,
                }
            return {
                "status_code": 0, "final_url": current_url, "headers": {}, "raw_html": "",
                "error": f"Redirect to unsafe host blocked: {reason}",
                "redirect_robots_blocked": False, "redirect_ssrf_blocked": True, "redirect_chain": redirect_chain,
                "redirect_scope": "ssrf_blocked", "retries": total_retries,
            }

        current_parsed = urlparse(current_url)
        origin = (current_parsed.scheme.lower(), current_parsed.netloc.lower())
        _apply_politeness(origin, deadline=deadline, throttler=throttler)

        # Attempt fetch with bounded retries on transient errors
        attempt = 0
        response_obj = None
        http_err = None
        net_err = None

        while attempt <= max_retries:
            op_timeout = _deadline_timeout(PAGE_TIMEOUT, deadline=deadline)
            if op_timeout <= 0.0:
                return {
                    "status_code": 0, "final_url": current_url, "headers": {}, "raw_html": "",
                    "error": "runtime_budget_exhausted",
                    "redirect_robots_blocked": False, "redirect_chain": redirect_chain,
                    "redirect_scope": "none", "retries": total_retries,
                }
            request = Request(current_url, headers={"User-Agent": USER_AGENT})
            if validated_ip:
                request.pinned_ip = validated_ip
            fetch_start = time.monotonic()
            try:
                response_obj = _open_url(request, op_timeout)
                fetch_latency = time.monotonic() - fetch_start
                (throttler or _DEFAULT_THROTTLER).record_outcome(origin, status_code=200, latency=fetch_latency)
                http_err = None
                net_err = None
                break
            except StopIteration:
                break
            except HTTPError as exc:
                fetch_latency = time.monotonic() - fetch_start
                (throttler or _DEFAULT_THROTTLER).record_outcome(origin, status_code=exc.code, latency=fetch_latency)
                http_err = exc
                if exc.code in (429, 500, 502, 503, 504) and attempt < max_retries:
                    attempt += 1
                    total_retries += 1
                    _deadline_sleep(0.01 * (2 ** attempt), deadline=deadline)
                    continue
                break
            except (URLError, TimeoutError, OSError) as exc:
                fetch_latency = time.monotonic() - fetch_start
                (throttler or _DEFAULT_THROTTLER).record_outcome(origin, status_code=0, latency=fetch_latency, is_error=True)
                net_err = exc
                if attempt < max_retries:
                    attempt += 1
                    total_retries += 1
                    _deadline_sleep(0.01 * (2 ** attempt), deadline=deadline)
                    continue
                break

        if response_obj is None:
            if http_err is not None:
                exc = http_err
                if exc.code in (301, 302, 303, 307, 308):
                    location = exc.headers.get("Location") if exc.headers else None
                    if not location:
                        return {"status_code": exc.code, "final_url": current_url, "headers": {}, "raw_html": "", "error": f"HTTP {exc.code} redirect without Location header", "redirect_robots_blocked": False, "redirect_chain": redirect_chain, "redirect_scope": "invalid", "retries": total_retries}
                    redirect_chain.append(current_url)
                    if redirects >= MAX_REDIRECTS:
                        return {"status_code": 0, "final_url": current_url, "headers": {}, "raw_html": "", "error": "Maximum redirect limit exceeded", "redirect_robots_blocked": False, "redirect_chain": redirect_chain, "redirect_scope": "max_exceeded", "retries": total_retries}
                    next_url = urljoin(current_url, location)
                    next_parsed = urlparse(next_url)
                    if next_parsed.scheme not in ("http", "https") or not next_parsed.netloc:
                        return {"status_code": 0, "final_url": next_url, "headers": {}, "raw_html": "", "error": "Redirected to an invalid URL", "redirect_robots_blocked": False, "redirect_chain": redirect_chain, "redirect_scope": "invalid", "retries": total_retries}

                    # Validate safety of redirect destination
                    dest_safe, dest_validated_ip, dest_reason = _is_safe_url(next_url, allow_localhost=allow_localhost, deadline=deadline, dns_cache=dns_cache)
                    if not dest_safe:
                        if dest_reason == "runtime_budget_exhausted":
                            return {"status_code": 0, "final_url": next_url, "headers": {}, "raw_html": "", "error": "runtime_budget_exhausted", "redirect_robots_blocked": False, "redirect_chain": redirect_chain, "redirect_scope": "none", "retries": total_retries}
                        return {"status_code": 0, "final_url": next_url, "headers": {}, "raw_html": "", "error": f"Redirect to unsafe host blocked: {dest_reason}", "redirect_robots_blocked": False, "redirect_ssrf_blocked": True, "redirect_chain": redirect_chain, "redirect_scope": "ssrf_blocked", "retries": total_retries}

                    # Check crawl scope: if target_host is provided and destination leaves host, stop before fetch
                    if target_host is not None:
                        cand_p = next_parsed.port or (443 if next_parsed.scheme == "https" else 80)
                        if not _host_in_scope(next_parsed.hostname, target_host, candidate_port=cand_p, candidate_scheme=next_parsed.scheme):
                            return {"status_code": exc.code, "final_url": next_url, "headers": dict(exc.headers.items()) if exc.headers else {}, "raw_html": "", "error": "external_redirect_out_of_scope", "redirect_robots_blocked": False, "redirect_chain": redirect_chain, "redirect_scope": "external", "retries": total_retries}

                    robots_result = robots_cache.get_robots(next_parsed, allow_localhost=allow_localhost, deadline=deadline)
                    if not robots_cache.allows(next_url, robots_result=robots_result):
                        reason = robots_result.get("error", robots_result.get("status"))
                        return {"status_code": 0, "final_url": next_url, "headers": {}, "raw_html": "", "error": f"Redirect target robots.txt is not safely crawlable ({reason})", "redirect_robots_blocked": True, "redirect_chain": redirect_chain, "redirect_scope": "robots_blocked", "retries": total_retries}
                    current_url = next_url
                    redirects += 1
                    continue
                return {
                    "status_code": exc.code,
                    "final_url": current_url,
                    "headers": dict(exc.headers.items()) if exc.headers else {},
                    "raw_html": "",
                    "error": f"HTTP {exc.code}",
                    "redirect_robots_blocked": False,
                    "redirect_chain": redirect_chain,
                    "redirect_scope": "same_origin" if not redirect_chain else "internal",
                    "retries": total_retries,
                }
            return {
                "status_code": 0, "final_url": current_url, "headers": {}, "raw_html": "",
                "error": str(net_err or "fetch_failed"), "redirect_robots_blocked": False,
                "redirect_chain": redirect_chain, "redirect_scope": "none", "retries": total_retries,
            }

        with response_obj as response:
            status = response.getcode()
            if status in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                if not location:
                    return {
                        "status_code": status, "final_url": current_url,
                        "headers": dict(response.headers.items()), "raw_html": "",
                        "error": f"HTTP {status} redirect without Location header",
                        "redirect_robots_blocked": False, "redirect_chain": redirect_chain,
                        "redirect_scope": "invalid", "retries": total_retries,
                    }
                redirect_chain.append(current_url)
                if redirects >= MAX_REDIRECTS:
                    return {
                        "status_code": 0, "final_url": current_url,
                        "headers": dict(response.headers.items()), "raw_html": "",
                        "error": "Maximum redirect limit exceeded",
                        "redirect_robots_blocked": False, "redirect_chain": redirect_chain,
                        "redirect_scope": "max_exceeded", "retries": total_retries,
                    }
                next_url = urljoin(current_url, location)
                next_parsed = urlparse(next_url)
                if next_parsed.scheme not in ("http", "https") or not next_parsed.netloc:
                    return {
                        "status_code": 0, "final_url": next_url, "headers": {}, "raw_html": "",
                        "error": "Redirected to an invalid URL",
                        "redirect_robots_blocked": False, "redirect_chain": redirect_chain,
                        "redirect_scope": "invalid", "retries": total_retries,
                    }

                # Check crawl scope: if target_host is provided and destination leaves host, stop before fetch
                if target_host is not None:
                    cand_p = next_parsed.port or (443 if next_parsed.scheme == "https" else 80)
                    if not _host_in_scope(next_parsed.hostname, target_host, candidate_port=cand_p, candidate_scheme=next_parsed.scheme):
                        return {
                            "status_code": status, "final_url": next_url,
                            "headers": dict(response.headers.items()), "raw_html": "",
                            "error": "external_redirect_out_of_scope",
                            "redirect_robots_blocked": False, "redirect_chain": redirect_chain,
                            "redirect_scope": "external", "retries": total_retries,
                        }

                # Validate safety of redirect destination
                dest_safe, dest_validated_ip, dest_reason = _is_safe_url(next_url, allow_localhost=allow_localhost, deadline=deadline, dns_cache=dns_cache)
                if not dest_safe:
                    return {
                        "status_code": 0, "final_url": next_url, "headers": {}, "raw_html": "",
                        "error": f"Redirect to unsafe host blocked: {dest_reason}",
                        "redirect_robots_blocked": False, "redirect_ssrf_blocked": True, "redirect_chain": redirect_chain,
                        "redirect_scope": "ssrf_blocked", "retries": total_retries,
                    }

                current_origin = (urlparse(current_url).scheme.lower(), urlparse(current_url).netloc.lower())
                next_origin = (next_parsed.scheme.lower(), next_parsed.netloc.lower())
                if next_origin != current_origin or redirects > 0:
                    robots_result = robots_cache.get_robots(next_parsed, allow_localhost=allow_localhost, deadline=deadline)
                elif robots_result is None:
                    robots_result = robots_cache.get_robots(next_parsed, allow_localhost=allow_localhost, deadline=deadline)
                if not robots_cache.allows(next_url, robots_result=robots_result):
                    reason = robots_result.get("error", robots_result.get("status"))
                    return {
                        "status_code": 0, "final_url": next_url, "headers": {}, "raw_html": "",
                        "error": f"Redirect target robots.txt is not safely crawlable ({reason})",
                        "redirect_robots_blocked": True, "redirect_chain": redirect_chain,
                        "redirect_scope": "robots_blocked", "retries": total_retries,
                    }
                current_url = next_url
                redirects += 1
                continue

            red_scope = "same_origin"
            if redirect_chain:
                orig_host = urlparse(redirect_chain[0]).netloc.lower()
                final_host = urlparse(response.geturl() or current_url).netloc.lower()
                red_scope = "internal" if orig_host == final_host else "external"

            # Requirement 6: Content-Type safety
            raw_ct = response.headers.get("Content-Type") or response.headers.get("content-type") or ""
            normalized_ct = raw_ct.split(";")[0].strip().lower()

            unsupported_prefixes = (
                "application/pdf", "image/", "video/", "audio/", "application/zip",
                "application/octet-stream", "binary/", "application/msword", "application/vnd"
            )

            is_html = False
            is_unsupported = False
            raw_payload = ""

            if normalized_ct in ("text/html", "application/xhtml+xml"):
                is_html = True
                is_unsupported = False
                raw_payload = _read_limited(response, max_bytes=max_response_bytes)
            elif normalized_ct and any(normalized_ct.startswith(p) for p in unsupported_prefixes):
                is_html = False
                is_unsupported = True
                raw_payload = ""
            elif normalized_ct in ("application/xml", "text/xml"):
                is_html = False
                is_unsupported = False
                raw_payload = _read_limited(response, max_bytes=max_response_bytes)
            else:
                # Missing or unknown Content-Type: do not blindly classify as HTML!
                # Sniff the payload conservatively for core HTML structural markers or XML
                sample = _read_limited(response, max_bytes=max_response_bytes)
                sample_sniff = sample[:1024].lstrip().lower()
                has_html_markers = any(m in sample_sniff for m in ("<!doctype html", "<html", "<head", "<body"))
                has_xml_markers = sample_sniff.startswith("<?xml") or any(m in sample_sniff for m in ("<sitemapindex", "<urlset", "<rss", "<feed"))
                if has_html_markers:
                    is_html = True
                    is_unsupported = False
                    raw_payload = sample
                elif has_xml_markers:
                    is_html = False
                    is_unsupported = False  # Valid for dedicated XML/sitemap parsing, but not HTML
                    raw_payload = sample
                else:
                    is_html = False
                    is_unsupported = True
                    raw_payload = ""

            return {
                "status_code": status,
                "final_url": response.geturl() or current_url,
                "headers": dict(response.headers.items()),
                "content_type": normalized_ct,
                "is_unsupported_content_type": is_unsupported,
                "raw_html": raw_payload if not is_unsupported else "",
                "error": None,
                "redirect_robots_blocked": False,
                "redirect_chain": redirect_chain,
                "redirect_scope": red_scope,
                "retries": total_retries,
            }


def check_soft_block(html, status_code):
    """Detects soft-block / challenge / CAPTCHA responses returning HTTP 200."""
    if status_code != 200 or not html:
        return False
    lower_html = html[:8000].lower()
    challenge_signals = [
        "cf-challenge-running", "challenge-form", "captcha", "security check",
        "please verify you are a human", "access denied", "ddos protection by cloudflare",
        "checking your browser before accessing", "bot protection", "just a moment..."
    ]
    matched = sum(1 for s in challenge_signals if s in lower_html)
    
    noindex = "noindex" in lower_html and ("nofollow" in lower_html or "noarchive" in lower_html)
    text = crawl_detector.readable_text(html)
    
    if noindex and len(text) < 1000 and matched >= 1:
        return True

    if len(text) < 1000 and matched >= 1:
        return True

    return matched >= 2 or ("cf-challenge" in lower_html)


def extract_canonical(html):
    """Extracts href from first <link rel='canonical'>."""
    if not html:
        return ""
    m = re.search(r'<link\b[^>]*?\brel=["\']canonical["\'][^>]*?\bhref=["\']([^"\']*)["\']', html, re.I)
    if not m:
        m = re.search(r'<link\b[^>]*?\bhref=["\']([^"\']*)["\'][^>]*?\brel=["\']canonical["\']', html, re.I)
    return m.group(1).strip() if m else ""


def build_page_profile(requested_url, fetch_result, audited_at, depth=0, role_hint=None):
    """Constructs a normalized PageProfile contract for a successfully fetched page."""
    final_url = fetch_result.get("final_url") or requested_url
    html = fetch_result.get("raw_html") or ""
    status_code = fetch_result.get("status_code", 0)
    headers = fetch_result.get("headers", {})
    content_type = fetch_result.get("content_type", "")
    is_unsupported = fetch_result.get("is_unsupported_content_type", False)

    canonical = extract_canonical(html) if not is_unsupported else ""
    inferred_role, role_reason = discovery_detector.classify_url_role(final_url)
    # Preserve an already-established upstream role when URL-only classification
    # is inconclusive/general. Detectors must consume the shared page context rather
    # than independently re-infer page intent from the URL.
    if is_unsupported:
        inferred_role = "unknown"
    elif role_hint and (not inferred_role or inferred_role == "general"):
        inferred_role = role_hint
    elif not inferred_role:
        inferred_role = "unknown"

    soft_blocked = check_soft_block(html, status_code) if not is_unsupported else False
    fetch_mode = "unsupported_content_type" if is_unsupported else "http_static"

    return {
        "url": final_url,
        "requested_url": requested_url,
        "final_url": final_url,
        "redirect_chain": fetch_result.get("redirect_chain", []),
        "redirect_scope": fetch_result.get("redirect_scope", "same_origin"),
        "canonical_url": canonical,
        "depth": depth,
        "fetch_mode": fetch_mode,
        "status_code": status_code,
        "headers": headers,
        "content_type": content_type,
        "static_html": html,
        "html": html,
        "rendered_html": None,
        "analysis_html": html,
        "analysis_source": "static",
        "audited_at": audited_at,
        "page_role": inferred_role,
        "page_intent": inferred_role,
        "is_soft_blocked": soft_blocked,
        "extraction_uncertain": soft_blocked,
        "analysis_confidence": "low" if soft_blocked else "normal",
    }


# ---------------------------------------------------------------------------
# Browser Fallback Escalation
# ---------------------------------------------------------------------------
def should_escalate_to_browser(profile):
    """
    Decide whether static HTML is insufficiently trustworthy for absence claims.

    Escalate on generic rendering-risk combinations, not site/domain names:
      - empty application mounts with little static text;
      - very low text density with heavy inline scripts;
      - known hydration/framework markers with very low text density;
      - a framework/app-shell signal combined with several external scripts and
        limited semantic text (covers substantial-but-incomplete HTML shells);
      - explicit loading/JavaScript-required copy combined with client assets.

    Rich static pages remain in HTTP mode even when they reference many scripts.
    """
    html = profile.get("html", "") or ""
    if not html:
        return False, "no_html"

    text = crawl_detector.readable_text(html)
    lower_html = html.lower()

    root_match = re.search(
        r'<(?:div|main|span)[^>]+id=["\'](?:root|app|__next|__nuxt)["\'][^>]*>(.*?)</(?:div|main|span)>',
        html, re.I | re.S
    )
    empty_root = bool(root_match and len(root_match.group(1).strip()) < 150)

    # Generic framework/app-shell evidence. These are structural signals that
    # recur across React, Next, Nuxt, Angular, Remix, Astro, Gatsby, Svelte and
    # common bundler/hydration output; they do not identify a particular site.
    framework_markers = (
        r'__next_data__', r'__next__', r'__nuxt__', r'data-reactroot',
        r'ng-version', r'webpackjsonp', r'webpack-runtime', r'@vite/',
        r'__remixcontext', r'__gatsby', r'astro-island', r'data-svelte',
        r'svelte-hydratable', r'nuxt-root', r'reactroot'
    )
    framework_signal_count = sum(1 for marker in framework_markers if re.search(marker, lower_html))
    hydration = framework_signal_count > 0

    scripts = len(re.findall(r'<script\b', lower_html))
    external_scripts = len(re.findall(r'<script\b[^>]+\bsrc=["\'][^"\']+["\']', lower_html))
    script_bytes = sum(
        len(m.group(0)) for m in re.finditer(r'<script\b[^>]*>.*?</script\s*>', html, re.I | re.S)
    )
    raw_bytes = max(len(html.encode("utf-8")), 1)
    text_len = len(text)
    text_ratio = max(text_len, 1) / raw_bytes
    script_ratio = script_bytes / raw_bytes

    has_app_mount = bool(re.search(r'<(?:div|main|span)[^>]+id=["\'](?:root|app|__next|__nuxt)["\']', lower_html))
    has_main_content = bool(re.search(r'<(?:main|article)\b[^>]*>\s*\S', html, re.I | re.S))
    loading_marker = bool(re.search(
        r"loading(?:\.\.\.|…)|please enable javascript|javascript required|enable javascript|skeleton|waiting for javascript|rendering application",
        lower_html, re.I
    ))

    # Existing high-confidence shell signals.
    if empty_root and text_len < 1000:
        return True, "empty_root_low_static_text"
    if text_ratio < 0.05 and script_ratio > 0.3:
        return True, "script_heavy_low_text_ratio"
    if hydration and text_ratio < 0.05:
        return True, "hydration_with_very_low_text"
    if text_len < 150 and scripts > 0:
        return True, "virtually_empty_with_scripts"

    # Generic substantial-but-incomplete shell: enough HTML exists to look
    # populated, but the document still strongly resembles a client-rendered
    # application and has limited semantic content. This is intentionally
    # conservative to avoid rendering ordinary content-heavy pages.
    if (framework_signal_count >= 1 and external_scripts >= 4
            and (text_ratio < 0.12 or text_len < 900)
            and (not has_main_content or text_len < 1400)):
        return True, "framework_external_scripts_limited_static_text"

    if (has_app_mount and external_scripts >= 3 and not has_main_content
            and text_len < 1200):
        return True, "app_shell_external_scripts_limited_static_text"

    if loading_marker and external_scripts >= 2 and text_len < 1500:
        return True, "loading_marker_with_client_assets"

    return False, "static_content_sufficient"


def render_with_browser(url, target_host=None, robots_cache=None, allow_localhost=False, deadline=None, timeout=5, dns_cache=None):
    """
    Safely render a page through Playwright after centralized URL validation.

    Browser subrequests are intercepted as an additional SSRF/scope and read-only guard:
    arbitrary pages must not cause the audit browser to reach internal, off-scope,
    or state-changing destinations (POST/PUT/PATCH/DELETE/etc.).
    """
    if deadline is not None and time.monotonic() >= deadline:
        return None, False, "browser_safety_rejected: runtime_budget_exhausted"

    valid, reason = validate_navigation_target(
        url,
        target_host=target_host,
        robots_cache=robots_cache,
        allow_localhost=allow_localhost,
        deadline=deadline,
        dns_cache=dns_cache,
    )
    if not valid:
        return None, False, f"browser_safety_rejected: {reason}"

    remaining = float(timeout)
    if deadline is not None:
        remaining = min(
            remaining,
            max(0.0, deadline - time.monotonic()),
        )

    if remaining <= 0:
        return None, False, "browser_safety_rejected: runtime_budget_exhausted"

    _SAFE_READ_METHODS = frozenset({"GET", "HEAD"})

    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            if deadline is not None and time.monotonic() >= deadline:
                return None, False, "browser_safety_rejected: runtime_budget_exhausted"

            rem_ms = max(1, int(remaining * 1000))
            try:
                browser = p.chromium.launch(headless=True, timeout=rem_ms)
            except TypeError:
                browser = p.chromium.launch(headless=True)
            except Exception as exc:
                return None, False, f"playwright_launch_failed: {type(exc).__name__}"

            try:
                if deadline is not None and time.monotonic() >= deadline:
                    try:
                        browser.close()
                    except Exception:
                        pass
                    return None, False, "browser_safety_rejected: runtime_budget_exhausted"

                try:
                    page = browser.new_page()
                except Exception as exc:
                    try:
                        browser.close()
                    except Exception:
                        pass
                    return None, False, f"playwright_page_creation_failed: {type(exc).__name__}"

                def handle_request(route):
                    request = route.request
                    req_method = (request.method or "").upper()
                    if req_method not in _SAFE_READ_METHODS:
                        route.abort()
                        return

                    request_url = request.url
                    parsed_request = urlparse(request_url)
                    request_host = (parsed_request.hostname or "").lower().rstrip(".")

                    safe = (
                        parsed_request.scheme in _SAFE_SCHEMES
                        and bool(request_host)
                        and (
                            target_host is None
                            or _host_in_scope(
                                request_host,
                                target_host,
                                candidate_port=parsed_request.port or (443 if parsed_request.scheme == "https" else 80),
                                candidate_scheme=parsed_request.scheme,
                            )
                        )
                        and _is_safe_url(
                            request_url,
                            allow_localhost=allow_localhost,
                            deadline=deadline,
                            dns_cache=dns_cache,
                        )[0]
                    )

                    if safe:
                        route.continue_()
                    else:
                        route.abort()

                page.route("**/*", handle_request)

                curr_remaining = float(timeout)
                if deadline is not None:
                    curr_remaining = min(
                        curr_remaining,
                        max(0.0, deadline - time.monotonic()),
                    )

                if curr_remaining <= 0:
                    try:
                        browser.close()
                    except Exception:
                        pass
                    return None, False, "browser_safety_rejected: runtime_budget_exhausted"

                page.goto(
                    url,
                    timeout=max(1, int(curr_remaining * 1000)),
                    wait_until="domcontentloaded",
                )

                if deadline is not None and time.monotonic() >= deadline:
                    try:
                        browser.close()
                    except Exception:
                        pass
                    return None, False, "browser_safety_rejected: runtime_budget_exhausted"

                try:
                    content = page.content()
                except Exception as exc:
                    try:
                        browser.close()
                    except Exception:
                        pass
                    return None, False, f"playwright_content_failed: {type(exc).__name__}"

                try:
                    browser.close()
                except Exception:
                    pass
                return content, True, None
            except Exception:
                try:
                    browser.close()
                except Exception:
                    pass
                raise

    except ImportError:
        return None, False, "playwright_unavailable"
    except Exception as exc:
        return None, False, f"playwright_error: {type(exc).__name__}"


# ---------------------------------------------------------------------------
# Bounded Sitemap Index Traversal
# ---------------------------------------------------------------------------
def fetch_sitemap_tree(root_url, robots_content, robots_result, allow_localhost=False, robots_cache=None, deadline=None, dns_cache=None, throttler=None):
    """
    Discovers declared sitemaps from robots.txt or falls back to /sitemap.xml.
    Recursively fetches XML sitemaps and resolves sitemap indexes up to bounded limits:
      MAX_SITEMAPS = 10
      MAX_SITEMAP_DEPTH = 3
      MAX_SITEMAP_URLS = 100
      MAX_SITEMAP_RESPONSE_BYTES = 2 * 1024 * 1024
    Applies per-origin robots checks for cross-origin sitemaps, obeys global deadline.
    Returns (discovered_urls, sitemap_xml_sample, sitemap_coverage).
    """
    if robots_cache is None:
        robots_cache = RobotsCache()
        if robots_result:
            parsed_root = urlparse(root_url)
            robots_cache._cache[(parsed_root.scheme.lower(), parsed_root.netloc.lower())] = robots_result

    declared = discovery_detector.extract_sitemap_urls_from_robots(robots_content)
    parsed_root = urlparse(root_url)
    sitemap_targets = [urljoin(root_url, u) for u in declared]
    if not sitemap_targets:
        sitemap_targets.append(f"{parsed_root.scheme}://{parsed_root.netloc}/sitemap.xml")

    discovered_urls = []
    seen_sitemaps = set()
    sitemap_sample = ""
    sitemaps_fetched = 0
    sitemaps_skipped = 0
    limit_reached = False
    max_depth_seen = 0

    # Queue of (sitemap_url, depth)
    queue = [(sm_url, 0) for sm_url in sitemap_targets]

    while queue and len(seen_sitemaps) < MAX_SITEMAPS:
        if deadline is not None and time.monotonic() >= deadline:
            limit_reached = True
            break

        sm_url, sm_depth = queue.pop(0)
        norm_sm = discovery_detector.normalize_url(sm_url)
        if norm_sm in seen_sitemaps:
            continue
        seen_sitemaps.add(norm_sm)
        max_depth_seen = max(max_depth_seen, sm_depth)

        # Check origin robots policy for this sitemap URL
        sm_parsed = urlparse(sm_url)
        sm_origin_robots = robots_cache.get_robots(sm_parsed, allow_localhost=allow_localhost, deadline=deadline)
        if not robots_cache.allows(sm_url, robots_result=sm_origin_robots):
            sitemaps_skipped += 1
            continue

        res = fetch_page(
            sm_url, allow_localhost=allow_localhost, robots_cache=robots_cache,
            deadline=deadline, max_response_bytes=MAX_SITEMAP_RESPONSE_BYTES,
            dns_cache=dns_cache, throttler=throttler
        )
        if res.get("status_code") == 200 and res.get("raw_html"):
            sitemaps_fetched += 1
            xml_text = res["raw_html"]
            if not sitemap_sample:
                sitemap_sample = xml_text
            urls, child_sms = discovery_detector.parse_sitemap_xml(xml_text)
            for u in urls:
                abs_u = urljoin(sm_url, u)
                if len(discovered_urls) < MAX_SITEMAP_URLS:
                    discovered_urls.append(abs_u)
                else:
                    limit_reached = True
                    break

            if sm_depth + 1 <= MAX_SITEMAP_DEPTH:
                for child_url in child_sms:
                    abs_child = urljoin(sm_url, child_url)
                    norm_child = discovery_detector.normalize_url(abs_child)
                    if norm_child not in seen_sitemaps and (len(seen_sitemaps) + len(queue)) < MAX_SITEMAPS:
                        queue.append((abs_child, sm_depth + 1))
                    elif (len(seen_sitemaps) + len(queue)) >= MAX_SITEMAPS:
                        limit_reached = True
        else:
            sitemaps_skipped += 1

    if queue or len(seen_sitemaps) >= MAX_SITEMAPS:
        limit_reached = True

    sitemap_coverage = {
        "attempted": True,
        "sources": sitemap_targets,
        "sitemaps_fetched": sitemaps_fetched,
        "sitemaps_skipped": sitemaps_skipped,
        "urls_discovered": len(discovered_urls),
        "limit_reached": limit_reached,
        "sitemap_depth": max_depth_seen,
    }

    return discovered_urls, sitemap_sample, sitemap_coverage


SAFETY_MARGIN_SECONDS = 2.0


def _finding(title, severity, evidence, summary, priority=None, rule_id=None):
    res = {
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "suggested_action": {"summary": summary, "priority": priority or severity},
    }
    if rule_id:
        res["rule_id"] = rule_id
    return res


def _inject_provenance(findings, profile):
    for f in findings:
        f.setdefault("source_url", profile.get("final_url", ""))
        f.setdefault("page_role", profile.get("page_role", "unknown"))
        f.setdefault("final_url_after_redirects", profile.get("final_url", ""))
        f.setdefault("canonical_url", profile.get("canonical_url", ""))
        f.setdefault("page_intent", profile.get("page_intent", "unknown"))
        f.setdefault("depth", profile.get("depth", 0))
        f.setdefault("fetch_mode", profile.get("fetch_mode", "unknown"))
        f.setdefault("analysis_source", profile.get("analysis_source", "unknown"))
        f.setdefault("extraction_uncertain", profile.get("extraction_uncertain", False))
        f.setdefault("is_soft_blocked", profile.get("is_soft_blocked", False))


def _check_redirect_chain(requested_url, fetch_res):
    redirect_chain = fetch_res.get("redirect_chain", [])
    if len(redirect_chain) >= 2:
        hop_count = len(redirect_chain)
        final_url = fetch_res.get("final_url", requested_url)
        f = _finding(
            "Redirect Chain Adds Multiple Navigation Hops", "medium",
            f"The requested URL followed {hop_count} HTTP redirect hops before reaching the final URL.",
            "Reduce unnecessary redirect hops and point internal references directly to the canonical destination.",
            "medium",
            rule_id="CR-REDIRECT-CHAIN-001"
        )
        f["source_url"] = requested_url
        f["redirect_chain"] = redirect_chain
        f["hop_count"] = hop_count
        f["final_url"] = final_url
        return f
    return None


def run_pipeline(target_url, rendered_html=None, enhanced=False, max_pages=DEFAULT_MAX_PAGES,
                 _allow_localhost=False, global_timeout=DEFAULT_GLOBAL_TIMEOUT):
    """
    Core entrypoint pipeline executing:
      1. SSRF Safety & URI validation
      2. Robots.txt policy inspection
      3. Primary seed fetch (with redirect tracking & final URL propagation)
      4. Single-page evaluation or multi-page priority crawl (depth <= 3, budget <= max_pages)
      5. Sitemap discovery & recursive index traversal
      6. Layered URL filtering, crawl-trap suppression & priority queue sequencing
      7. Multi-skill evaluation (crawl/render, schema, engagement, discovery, entity corroboration, content quality)
      8. Finding deduplication, severity normalization, evidence coverage reporting, and JSON report generation.
    """
    start_time = time.monotonic()
    # Reserve final safety margin for aggregation, schema validation, and report generation (Requirement 7)
    timeout_budget = float(global_timeout)
    margin = 12.0  # Increased margin for robust synthesis and post-crawl execution
    deadline = start_time + max(0.0, timeout_budget - margin)
    dns_cache = AuditDnsCache()
    run_throttler = OriginThrottler()

    audited_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return build_final_report(target_url, audited_at, [_finding(
            "Invalid Target URL", "critical", "The supplied target is not a complete HTTP or HTTPS URL.",
            "Provide a complete URL using the HTTP or HTTPS scheme.", "critical",
            rule_id="DISC-INVALID-URL-001"
        )], enhanced=enhanced)

    # SSRF safety check
    safe, validated_ip, reason = _is_safe_url(target_url, allow_localhost=_allow_localhost, deadline=deadline, dns_cache=dns_cache)
    if not safe:
        elapsed_s = round(time.monotonic() - start_time, 3)
        budget_exhausted = (reason == "runtime_budget_exhausted") or (time.monotonic() >= deadline) or (elapsed_s >= float(global_timeout))
        if budget_exhausted:
            cov_data = {
                "requested_url": target_url,
                "requested_page_budget": min(max(int(max_pages), 1), HARD_MAX_PAGES),
                "urls_seen_from_links": 0,
                "urls_seen_from_sitemap": 0,
                "urls_discovered_total": 1,
                "urls_discovered": 1,
                "urls_enqueued": 1,
                "urls_selected": 0,
                "urls_fetched": 0,
                "urls_failed": 0,
                "urls_skipped": 1,
                "urls_blocked_by_robots": 0,
                "pages_skipped": [{"url": target_url, "reason": "runtime_budget_exhausted"}],
                "stop_reason": "runtime_budget_exhausted",
                "crawl_stop_reason": "runtime_budget_exhausted",
                "stopping_condition": "runtime_budget_exhausted",
                "runtime_budget_seconds": int(float(global_timeout)),
                "runtime_elapsed_seconds": elapsed_s,
                "runtime_budget_exhausted": True,
                "sitemap": {"attempted": False},
            }
            return build_final_report(parsed.netloc or target_url, audited_at, [_finding(
                "Runtime Budget Exhausted", "medium",
                "The global runtime budget was exhausted before crawling could begin.",
                "Increase the global runtime budget to allow complete audit execution.",
                "medium",
                rule_id="CR-BUDGET-001"
            )], enhanced=enhanced, coverage_data=cov_data)
        return build_final_report(parsed.netloc or target_url, audited_at, [_finding(
            "Blocked Target URL", "critical",
            f"The target URL was rejected for safety: {reason}.",
            "Provide a public HTTP or HTTPS URL that does not resolve to a private or internal host.",
            "critical",
            rule_id="DISC-BLOCKED-URL-001"
        )], enhanced=enhanced)

    robots_cache = RobotsCache()
    raw_findings = []
    robots = robots_cache.get_robots(parsed, allow_localhost=_allow_localhost, deadline=deadline)
    robots_url = robots.get("url", "")
    robots_err = robots.get("error", robots.get("status", "unknown"))

    if not robots_cache.allows(target_url, robots_result=robots):
        elapsed_s = round(time.monotonic() - start_time, 3)
        budget_exhausted = (robots_err == "runtime_budget_exhausted") or (time.monotonic() >= deadline) or (elapsed_s >= float(global_timeout))
        cov_data = {
            "requested_url": target_url,
            "requested_page_budget": min(max(int(max_pages), 1), HARD_MAX_PAGES),
            "urls_seen_from_links": 0,
            "urls_seen_from_sitemap": 0,
            "urls_discovered_total": 1,
            "urls_discovered": 1,
            "urls_enqueued": 1,
            "urls_selected": 1,
            "urls_fetched": 0,
            "urls_failed": 0,
            "urls_skipped": 1,
            "urls_blocked_by_robots": 1,
            "pages_skipped": [{"url": target_url, "reason": "runtime_budget_exhausted" if budget_exhausted else "robots_blocked"}],
            "stop_reason": "runtime_budget_exhausted" if budget_exhausted else "robots_blocked",
            "crawl_stop_reason": "runtime_budget_exhausted" if budget_exhausted else "robots_blocked",
            "stopping_condition": "runtime_budget_exhausted" if budget_exhausted else "robots_blocked",
            "runtime_budget_seconds": int(float(global_timeout)),
            "runtime_elapsed_seconds": elapsed_s,
            "runtime_budget_exhausted": budget_exhausted,
            "sitemap": {"attempted": False},
        }
        if robots["status"] == "ok":
            raw_findings.append(_finding(
                "Content Blocked by robots.txt", "critical",
                f"robots.txt at {robots_url} disallows the target URL for user-agent {USER_AGENT}.",
                "Review robots.txt and allow crawling for paths intended to be discoverable by AI agents.", "critical",
                rule_id="CR-ROBOTS-001"
            ))
        else:
            # Inspect root cause of robots verification failure
            root_cause_msg = robots_err
            if "CERTIFICATE_VERIFY_FAILED" in robots_err:
                root_cause_msg = "TLS certificate verification failed"
            elif robots_err.startswith("HTTP "):
                http_error_code = robots_err.split(' ')[1]
                root_cause_msg = f"HTTP error {http_error_code}"
            elif "dns_resolution_failed" in robots_err or "gaierror" in robots_err:
                root_cause_msg = "DNS resolution failed"
            elif "timeout" in robots_err.lower():
                root_cause_msg = "Connection timed out"
                
            raw_findings.append(_finding(
                "Unable to Verify robots.txt Safety", "high",
                f"robots.txt at {robots_url} could not be safely verified ({robots_err}); the target page was not fetched.",
                "Restore a reachable robots.txt endpoint returning 200 or 404 so crawler permissions can be verified deterministically.", "high",
                rule_id="CR-ROBOTS-003",
            ))
            raw_findings[-1]["robots_error_detail"] = root_cause_msg
        return build_final_report(parsed.netloc, audited_at, raw_findings, enhanced=enhanced, coverage_data=cov_data)

    # Fetch seed page
    page = fetch_page(target_url, robots, allow_localhost=_allow_localhost, robots_cache=robots_cache, deadline=deadline, dns_cache=dns_cache, throttler=run_throttler)
    final_url = page.get("final_url", target_url)
    rc_finding = _check_redirect_chain(target_url, page)
    if rc_finding:
        raw_findings.append(rc_finding)
    if page.get("redirect_ssrf_blocked"):
        elapsed_s = round(time.monotonic() - start_time, 3)
        cov_data = {
            "requested_url": target_url,
            "requested_page_budget": min(max(int(max_pages), 1), HARD_MAX_PAGES),
            "urls_discovered_total": 1, "urls_discovered": 1, "urls_enqueued": 1, "urls_selected": 1,
            "urls_fetched": 0, "urls_failed": 1, "urls_skipped": 1,
            "urls_rejected_for_ssrf": 1,
            "pages_skipped": [{"url": final_url, "reason": page.get("error") or "redirect_ssrf_blocked"}],
            "stop_reason": "redirect_ssrf_blocked", "crawl_stop_reason": "redirect_ssrf_blocked",
            "stopping_condition": "redirect_ssrf_blocked",
            "runtime_budget_seconds": int(float(global_timeout)),
            "runtime_elapsed_seconds": elapsed_s, "runtime_budget_exhausted": False,
            "sitemap": {"attempted": False},
        }
        raw_findings.append(_finding(
            "Redirect Target Blocked for SSRF Safety", "critical",
            f"A redirect from {target_url} led to {final_url}, which was rejected by SSRF/network safety validation: {page.get('error') or 'unsafe target'}.",
            "Ensure redirect targets resolve to public network destinations and do not cross the audit security boundary.", "critical",
            rule_id="DISC-BLOCKED-URL-001"
        ))
        return build_final_report(urlparse(final_url).netloc or parsed.netloc, audited_at, raw_findings, enhanced=enhanced, coverage_data=cov_data)

    if page.get("redirect_robots_blocked"):
        elapsed_s = round(time.monotonic() - start_time, 3)
        budget_exhausted = (page.get("error") == "runtime_budget_exhausted") or (time.monotonic() >= deadline) or (elapsed_s >= float(global_timeout))
        cov_data = {
            "requested_url": target_url,
            "requested_page_budget": min(max(int(max_pages), 1), HARD_MAX_PAGES),
            "urls_seen_from_links": 0,
            "urls_seen_from_sitemap": 0,
            "urls_discovered_total": 1,
            "urls_discovered": 1,
            "urls_enqueued": 1,
            "urls_selected": 1,
            "urls_fetched": 0,
            "urls_failed": 0,
            "urls_skipped": 1,
            "urls_blocked_by_robots": 1,
            "pages_skipped": [{"url": final_url, "reason": page.get("error") or "redirect_robots_blocked"}],
            "stop_reason": "runtime_budget_exhausted" if budget_exhausted else "redirect_robots_blocked",
            "crawl_stop_reason": "runtime_budget_exhausted" if budget_exhausted else "redirect_robots_blocked",
            "stopping_condition": "runtime_budget_exhausted" if budget_exhausted else "redirect_robots_blocked",
            "runtime_budget_seconds": int(float(global_timeout)),
            "runtime_elapsed_seconds": elapsed_s,
            "runtime_budget_exhausted": budget_exhausted,
            "sitemap": {"attempted": False},
        }
        raw_findings.append(_finding(
            "Redirect Target Blocked by robots.txt", "high",
            f"A redirect from {target_url} led to {final_url}, whose robots.txt could not be safely verified or disallowed crawling.",
            "Ensure every redirect target that should be audited permits crawler access in its robots.txt policy.", "high",
            rule_id="CR-ROBOTS-002"
        ))
        return build_final_report(urlparse(final_url).netloc, audited_at, raw_findings, enhanced=enhanced, coverage_data=cov_data)

    if page["status_code"] != 200:
        elapsed_s = round(time.monotonic() - start_time, 3)
        budget_exhausted = (page.get("error") == "runtime_budget_exhausted") or (time.monotonic() >= deadline) or (elapsed_s >= float(global_timeout))
        cov_data = {
            "requested_url": target_url,
            "requested_page_budget": min(max(int(max_pages), 1), HARD_MAX_PAGES),
            "urls_seen_from_links": 0,
            "urls_seen_from_sitemap": 0,
            "urls_discovered_total": 1,
            "urls_discovered": 1,
            "urls_enqueued": 1,
            "urls_selected": 1,
            "urls_fetched": 0,
            "urls_failed": 1,
            "urls_skipped": 1,
            "pages_skipped": [{"url": target_url, "reason": page.get("error") or f"http_status_{page.get('status_code')}"}],
            "stop_reason": "runtime_budget_exhausted" if budget_exhausted else "seed_fetch_failed",
            "crawl_stop_reason": "runtime_budget_exhausted" if budget_exhausted else "seed_fetch_failed",
            "stopping_condition": "runtime_budget_exhausted" if budget_exhausted else "seed_fetch_failed",
            "runtime_budget_seconds": int(float(global_timeout)),
            "runtime_elapsed_seconds": elapsed_s,
            "runtime_budget_exhausted": budget_exhausted,
            "sitemap": {"attempted": False},
        }
        status = page["status_code"] or "network failure"
        sev = "critical" if isinstance(status, int) and status >= 500 else "high"
        raw_findings.append(_finding(
            f"Target Page Fetch Failed ({status})", sev,
            f"The target URL returned {status}; no successful page payload was available for content analysis.",
            "Ensure the public target URL returns a successful HTML response to crawlers and users.", sev,
            rule_id="CR-STATUS-001"
        ))
        return build_final_report(urlparse(final_url).netloc, audited_at, raw_findings, enhanced=enhanced, coverage_data=cov_data)

    # Build primary seed PageProfile
    seed_profile = build_page_profile(target_url, page, audited_at, depth=0, role_hint="homepage")
    target_host = urlparse(final_url).netloc.lower()

    if rendered_html is not None:
        seed_profile["rendered_html"] = rendered_html
        seed_profile["html"] = rendered_html
        seed_profile["analysis_html"] = rendered_html
        seed_profile["analysis_source"] = "rendered"
        seed_profile["fetch_mode"] = "browser"
        seed_profile["render_escalated"] = True
        seed_profile["render_reason"] = "external_rendered_html_provided"
    else:
        # Check browser escalation for seed page
        escalate, esc_reason = should_escalate_to_browser(seed_profile)
        if escalate and time.monotonic() < deadline:
            r_html, r_avail, r_err = render_with_browser(
                final_url, target_host=target_host, robots_cache=robots_cache,
                allow_localhost=_allow_localhost, deadline=deadline, dns_cache=dns_cache
            )
            if r_html:
                seed_profile["raw_text_length"] = len(crawl_detector.readable_text(page.get("raw_html", "")))
                seed_profile["rendered_html"] = r_html
                seed_profile["html"] = r_html
                seed_profile["analysis_html"] = r_html
                seed_profile["analysis_source"] = "rendered"
                seed_profile["fetch_mode"] = "browser"
                seed_profile["render_escalated"] = True
                seed_profile["render_reason"] = esc_reason
                seed_profile["rendered_text_length"] = len(crawl_detector.readable_text(r_html))
                seed_profile["text_gap"] = seed_profile["rendered_text_length"] - seed_profile["raw_text_length"]
            else:
                seed_profile["browser_available"] = r_avail
                seed_profile["render_fallback_reason"] = r_err
                seed_profile["extraction_uncertain"] = True
                seed_profile["analysis_confidence"] = "low"

    page_artifacts = [seed_profile]

    # Run primary page detectors only for supported HTML content and non-challenge pages (Requirement 6 & 13)
    is_spa_shell = False
    if seed_profile.get("fetch_mode") != "unsupported_content_type":
        if seed_profile.get("is_soft_blocked"):
            try:
                result = content_quality_detector.audit(seed_profile)
                findings = result.get("findings", [])
                _inject_provenance(findings, seed_profile)
                raw_findings.extend(findings)
            except Exception as exc:
                inc = _finding(
                    "Detector Execution Incomplete", "medium",
                    f"A focused detector could not complete safely for this page: {type(exc).__name__}.",
                    "Review the page payload for malformed markup and rerun the audit after correcting the underlying content.", "medium",
                    rule_id="CR-DETECTOR-INCOMPLETE-001"
                )
                _inject_provenance([inc], seed_profile)
                raw_findings.append(inc)
        else:
            try:
                crawl_res = crawl_detector.audit(seed_profile)
                crawl_findings = crawl_res.get("findings", [])
                _inject_provenance(crawl_findings, seed_profile)
                raw_findings.extend(crawl_findings)
                is_spa_shell = any(f.get("rule_id") == "CR-RENDER-SPA-001" for f in crawl_findings)
                seed_profile["is_spa_shell"] = is_spa_shell
            except Exception as exc:
                inc = _finding(
                    "Detector Execution Incomplete", "medium",
                    f"A focused detector could not complete safely for this page: {type(exc).__name__}.",
                    "Review the page payload for malformed markup and rerun the audit after correcting the underlying content.", "medium",
                    rule_id="CR-DETECTOR-INCOMPLETE-001"
                )
                _inject_provenance([inc], seed_profile)
                raw_findings.append(inc)

            # Do not unconditionally suppress positive findings when extraction is uncertain.
            # Detectors will individually handle absence findings.
            if not seed_profile.get("is_soft_blocked"):
                for detector in (schema_detector, engagement_detector, content_quality_detector):
                    try:
                        result = detector.audit(seed_profile)
                        findings = result.get("findings", [])
                        _inject_provenance(findings, seed_profile)
                        raw_findings.extend(findings)

                    except Exception as exc:
                        inc = _finding(
                            "Detector Execution Incomplete", "medium",
                            f"A focused detector could not complete safely for this page: {type(exc).__name__}.",
                            "Review the page payload for malformed markup and rerun the audit after correcting the underlying content.", "medium",
                            rule_id="CR-DETECTOR-INCOMPLETE-001"
                        )
                        _inject_provenance([inc], seed_profile)
                        raw_findings.append(inc)

    # Bounded multi-page crawl (when enhanced=True)
    pages_inspected = [{
        "url": final_url, "role": seed_profile["page_role"],
        "status": seed_profile["status_code"], "depth": 0,
        "final_url": final_url,
    }]
    pages_skipped = []
    stopping_condition = "single_page_audit"
    sitemap_meta = {"attempted": False}
    browser_pages_count = 1 if seed_profile.get("fetch_mode") == "browser" else 0
    max_depth_reached = 0

    # Explicit discovery tracking sets & counters
    urls_seen_from_sitemap = set()
    urls_seen_from_links = set()
    urls_selected_count = 1
    urls_rejected_for_scope = 0
    urls_rejected_for_ssrf = 0
    urls_rejected_as_trap = 0
    urls_rejected_as_duplicate = 0
    urls_rejected_for_budget = 0

    # Enforce safe bounds on max_pages
    safe_max_pages = min(max(int(max_pages), 1), HARD_MAX_PAGES)

    if enhanced:
        try:
            # 1. Discover & fetch sitemaps with recursive index traversal
            sitemap_urls, sitemap_sample, sitemap_meta = fetch_sitemap_tree(
                final_url, robots.get("content", ""), robots, allow_localhost=_allow_localhost,
                robots_cache=robots_cache, deadline=deadline, dns_cache=dns_cache, throttler=run_throttler
            )
            urls_seen_from_sitemap.update(sitemap_urls)

            # 2. Candidate priority queue
            visited_urls = {discovery_detector.normalize_url(final_url), discovery_detector.normalize_url(target_url)}
            candidate_queue = []  # list of tuples: (score, url, depth, role, reason)
            enqueued_urls = set(visited_urls)

            # Enqueue sitemap URLs (depth 1)
            for sm_url in sitemap_urls:
                valid, r_reason, norm_sm = discovery_detector.should_visit_url(
                    sm_url, base_url=final_url, visited_set=enqueued_urls, depth=1, max_depth=MAX_DEPTH, target_host=target_host
                )
                if valid and norm_sm not in enqueued_urls:
                    role, role_reason = discovery_detector.classify_url_role(norm_sm)
                    score = discovery_detector.score_url_priority(norm_sm, inferred_role=role, from_sitemap=True, depth=1)
                    candidate_queue.append((score, norm_sm, 1, role, "Sitemap URL"))
                    enqueued_urls.add(norm_sm)
                elif not valid:
                    if r_reason == "external_domain":
                        urls_rejected_for_scope += 1
                    elif "trap" in r_reason or "loop" in r_reason:
                        urls_rejected_as_trap += 1
                    elif r_reason == "already_visited":
                        urls_rejected_as_duplicate += 1

            # Enqueue seed HTML links (depth 1)
            try:
                raw_links = discovery_detector.extract_links_from_html(seed_profile["html"], base_url=final_url)
            except Exception as exc:
                raw_links = []
                inc = _finding(
                    "Detector Execution Incomplete", "medium",
                    f"A focused detector could not complete safely for this page: {type(exc).__name__}.",
                    "Review the page payload for malformed markup and rerun the audit after correcting the underlying content.", "medium",
                    rule_id="CR-DETECTOR-INCOMPLETE-001"
                )
                _inject_provenance([inc], seed_profile)
                raw_findings.append(inc)
            for href, anchor_text in raw_links:
                urls_seen_from_links.add(href)
                valid, r_reason, norm_link = discovery_detector.should_visit_url(
                    href, base_url=final_url, visited_set=enqueued_urls, depth=1, max_depth=MAX_DEPTH, target_host=target_host
                )
                if valid and norm_link not in enqueued_urls:
                    role, role_reason = discovery_detector.classify_url_role(norm_link, anchor_text)
                    score = discovery_detector.score_url_priority(norm_link, link_text=anchor_text, inferred_role=role, depth=1)
                    candidate_queue.append((score, norm_link, 1, role, role_reason))
                    enqueued_urls.add(norm_link)
                elif not valid:
                    if r_reason == "external_domain":
                        urls_rejected_for_scope += 1
                    elif "trap" in r_reason or "loop" in r_reason:
                        urls_rejected_as_trap += 1
                    elif r_reason == "already_visited":
                        urls_rejected_as_duplicate += 1

            # 3. Priority crawl loop
            host_failures = 0
            circuit_breaker_tripped = False
            runtime_exhausted = False

            while candidate_queue and len(page_artifacts) < safe_max_pages and not circuit_breaker_tripped:
                # Check global deadline before dequeuing
                if time.monotonic() >= deadline:
                    runtime_exhausted = True
                    break

                # Sort to pop candidate with highest priority score
                candidate_queue.sort(key=lambda x: x[0])
                score, cand_url, cand_depth, cand_role, cand_reason = candidate_queue.pop()
                urls_selected_count += 1

                norm_cand = discovery_detector.normalize_url(cand_url)
                if norm_cand in visited_urls:
                    urls_rejected_as_duplicate += 1
                    continue
                visited_urls.add(norm_cand)

                # Check host circuit breaker
                if host_failures >= CIRCUIT_BREAKER_THRESHOLD:
                    circuit_breaker_tripped = True
                    pages_skipped.append({"url": cand_url, "reason": "host_circuit_breaker_tripped"})
                    break

                # Check origin robots permissions
                cand_parsed = urlparse(cand_url)
                cand_robots = robots_cache.get_robots(cand_parsed, allow_localhost=_allow_localhost, deadline=deadline)
                if not robots_cache.allows(cand_url, robots_result=cand_robots):
                    pages_skipped.append({"url": cand_url, "reason": "robots_disallowed"})
                    continue

                # Fetch candidate page with scope enforcement
                sub_res = fetch_page(
                    cand_url, allow_localhost=_allow_localhost, robots_cache=robots_cache,
                    deadline=deadline, target_host=target_host, dns_cache=dns_cache, throttler=run_throttler
                )
                sub_status = sub_res.get("status_code", 0)
                sub_final = sub_res.get("final_url", cand_url)
                sub_final_parsed = urlparse(sub_final)
                
                sub_rc_finding = _check_redirect_chain(cand_url, sub_res)
                if sub_rc_finding:
                    raw_findings.append(sub_rc_finding)

                # Check if candidate redirect was rejected for out of scope
                if sub_res.get("error") == "external_redirect_out_of_scope" or sub_final_parsed.netloc.lower() != target_host:
                    urls_rejected_for_scope += 1
                    pages_skipped.append({"url": cand_url, "reason": "external_redirect_out_of_scope", "final_url": sub_final})
                    continue

                if sub_status == 200 and not sub_res.get("redirect_robots_blocked"):
                    host_failures = 0
                    max_depth_reached = max(max_depth_reached, cand_depth)
                    sub_profile = build_page_profile(cand_url, sub_res, audited_at, depth=cand_depth, role_hint=cand_role)

                    # Browser fallback escalation for subpages
                    if browser_pages_count < MAX_BROWSER_PAGES and time.monotonic() < deadline:
                        esc, esc_reas = should_escalate_to_browser(sub_profile)
                        if esc:
                            r_html, r_avail, r_err = render_with_browser(
                                sub_final, target_host=target_host, robots_cache=robots_cache,
                                allow_localhost=_allow_localhost, deadline=deadline, dns_cache=dns_cache
                            )
                            if r_html:
                                sub_profile["raw_text_length"] = len(crawl_detector.readable_text(sub_res.get("raw_html", "")))
                                sub_profile["rendered_html"] = r_html
                                sub_profile["html"] = r_html
                                sub_profile["analysis_html"] = r_html
                                sub_profile["analysis_source"] = "rendered"
                                sub_profile["fetch_mode"] = "browser"
                                sub_profile["render_escalated"] = True
                                sub_profile["render_reason"] = esc_reas
                                sub_profile["rendered_text_length"] = len(crawl_detector.readable_text(r_html))
                                sub_profile["text_gap"] = sub_profile["rendered_text_length"] - sub_profile["raw_text_length"]
                                browser_pages_count += 1
                            else:
                                sub_profile["browser_available"] = r_avail
                                sub_profile["render_fallback_reason"] = r_err
                                sub_profile["extraction_uncertain"] = True
                                sub_profile["analysis_confidence"] = "low"

                    page_artifacts.append(sub_profile)
                    pages_inspected.append({
                        "url": cand_url,
                        "role": sub_profile["page_role"],
                        "status": 200,
                        "depth": cand_depth,
                        "final_url": sub_profile["final_url"],
                    })

                    # Run per-page detectors only when content extraction is trustworthy.
                    # An unsuccessful render fallback must not become a cascade of
                    # unsupported absence findings.
                    # Detectors will handle extraction_uncertainty for absence finding suppression internally.
                    if (sub_profile.get("fetch_mode") != "unsupported_content_type"
                            and not sub_profile.get("is_soft_blocked")):
                        for det in (crawl_detector, schema_detector, engagement_detector):
                            try:
                                det_res = det.audit(sub_profile)
                                findings = det_res.get("findings", [])
                                _inject_provenance(findings, sub_profile)
                                raw_findings.extend(findings)
                            except Exception as exc:
                                inc = _finding(
                                    "Detector Execution Incomplete", "medium",
                                    f"A focused detector could not complete safely for this page: {type(exc).__name__}.",
                                    "Review the page payload for malformed markup and rerun the audit after correcting the underlying content.", "medium",
                                    rule_id="CR-DETECTOR-INCOMPLETE-001"
                                )
                                _inject_provenance([inc], sub_profile)
                                raw_findings.append(inc)

                    # Extract novel links from subpage if depth < MAX_DEPTH and time allows
                    if cand_depth < MAX_DEPTH and time.monotonic() < deadline and sub_profile.get("fetch_mode") != "unsupported_content_type":
                        try:
                            sub_links = discovery_detector.extract_links_from_html(sub_profile["html"], base_url=sub_profile["final_url"])
                        except Exception as exc:
                            sub_links = []
                            inc = _finding(
                                "Detector Execution Incomplete", "medium",
                                f"A focused detector could not complete safely for this page: {type(exc).__name__}.",
                                "Review the page payload for malformed markup and rerun the audit after correcting the underlying content.", "medium",
                                rule_id="CR-DETECTOR-INCOMPLETE-001"
                            )
                            _inject_provenance([inc], sub_profile)
                            raw_findings.append(inc)
                        for sub_href, sub_text in sub_links:
                            urls_seen_from_links.add(sub_href)
                            valid, r_reason, norm_sub = discovery_detector.should_visit_url(
                                sub_href, base_url=sub_profile["final_url"], visited_set=enqueued_urls,
                                depth=cand_depth + 1, max_depth=MAX_DEPTH, target_host=target_host
                            )
                            if valid and norm_sub not in enqueued_urls:
                                s_role, s_reason = discovery_detector.classify_url_role(norm_sub, sub_text)
                                s_score = discovery_detector.score_url_priority(
                                    norm_sub, link_text=sub_text, inferred_role=s_role, depth=cand_depth + 1
                                )
                                candidate_queue.append((s_score, norm_sub, cand_depth + 1, s_role, s_reason))
                                enqueued_urls.add(norm_sub)
                            elif not valid:
                                if r_reason == "external_domain":
                                    urls_rejected_for_scope += 1
                                elif "trap" in r_reason or "loop" in r_reason:
                                    urls_rejected_as_trap += 1
                                elif r_reason == "already_visited":
                                    urls_rejected_as_duplicate += 1
                else:
                    if sub_status >= 500 or sub_status == 0:
                        host_failures += 1
                    reason_code = f"http_status_{sub_status}" if sub_status else (sub_res.get("error") or "fetch_failed")
                    pages_skipped.append({"url": cand_url, "reason": reason_code})

            if candidate_queue:
                urls_rejected_for_budget = len(candidate_queue)

            if runtime_exhausted or time.monotonic() >= deadline:
                stopping_condition = "runtime_budget_exhausted"
            elif len(page_artifacts) >= safe_max_pages:
                stopping_condition = "page_budget_exhausted"
            elif circuit_breaker_tripped:
                stopping_condition = "circuit_breaker_tripped"
            else:
                stopping_condition = "source_exhaustion"

            # 4. Site Discovery detector evaluation (only for supported HTML and non-challenge pages)
            if (seed_profile.get("fetch_mode") != "unsupported_content_type"
                and not seed_profile.get("is_soft_blocked")
                and not is_spa_shell):
                discovery_res = discovery_detector.audit({
                    "url": target_url,
                    "html": seed_profile["html"],
                    "robots_content": robots.get("content", ""),
                    "sitemap_xml": sitemap_sample,
                    "page_budget": safe_max_pages,
                })
                raw_findings.extend(discovery_res.get("findings", []))

            # 5. Cross-page analysis: entity corroboration
            try:
                entity_res = entity_detector.audit({"page_artifacts": page_artifacts})
                raw_findings.extend(entity_res.get("findings", []))
            except Exception as exc:
                inc = _finding(
                    "Detector Execution Incomplete", "medium",
                    f"A focused detector could not complete safely for cross-page analysis: {type(exc).__name__}.",
                    "Review the site structure and rerun the audit.", "medium",
                    rule_id="CR-DETECTOR-INCOMPLETE-001"
                )
                inc["detector"] = "entity-corroboration"
                inc["status"] = "incomplete"
                inc["error_type"] = type(exc).__name__
                inc["scope"] = "cross_page"
                raw_findings.append(inc)

            # 6. Cross-page analysis: content quality (thin, duplicates, overlap)
            try:
                cq_res = content_quality_detector.audit({"page_artifacts": page_artifacts})
                for f in cq_res.get("findings", []):
                    raw_findings.append(f)
            except Exception as exc:
                inc = _finding(
                    "Detector Execution Incomplete", "medium",
                    f"A focused detector could not complete safely for cross-page analysis: {type(exc).__name__}.",
                    "Review the site structure and rerun the audit.", "medium",
                    rule_id="CR-DETECTOR-INCOMPLETE-001"
                )
                inc["detector"] = "content-quality"
                inc["status"] = "incomplete"
                inc["error_type"] = type(exc).__name__
                inc["scope"] = "cross_page"
                raw_findings.append(inc)

        except Exception:
            if runtime_exhausted or time.monotonic() >= deadline:
                stopping_condition = "runtime_budget_exhausted"
            else:
                stopping_condition = "execution_interrupted"

    raw_elapsed = time.monotonic() - start_time
    elapsed_seconds = round(raw_elapsed, 3)
    runtime_exhausted_flag = (stopping_condition == "runtime_budget_exhausted") or (time.monotonic() >= deadline) or (raw_elapsed >= float(global_timeout))
    if runtime_exhausted_flag and stopping_condition not in ("page_budget_exhausted", "circuit_breaker_tripped"):
        stopping_condition = "runtime_budget_exhausted"

    all_discovered_set = urls_seen_from_sitemap | urls_seen_from_links | {target_url, final_url}
    total_discovered_count = max(len(all_discovered_set), len(pages_inspected) + len(pages_skipped))

    coverage_data = {
        "requested_url": target_url,
        "requested_page_budget": safe_max_pages,
        "urls_seen_from_links": len(urls_seen_from_links),
        "urls_seen_from_sitemap": len(urls_seen_from_sitemap),
        "urls_discovered_total": total_discovered_count,
        "urls_discovered": total_discovered_count,
        "urls_enqueued": len(enqueued_urls) if enhanced else 1,
        "urls_selected": urls_selected_count,
        "urls_fetched": len(page_artifacts),
        "urls_failed": sum(1 for p in pages_skipped if p.get("reason", "").startswith("http_status_5") or p.get("reason") in ("fetch_failed", "timeout", "network_failure")),
        "urls_skipped": len(pages_skipped),
        "urls_blocked_by_robots": sum(1 for p in pages_skipped if p.get("reason") == "robots_disallowed"),
        "urls_rejected_for_scope": urls_rejected_for_scope,
        "urls_rejected_for_ssrf": urls_rejected_for_ssrf,
        "urls_rejected_as_trap": urls_rejected_as_trap,
        "urls_rejected_as_duplicate": urls_rejected_as_duplicate,
        "urls_rejected_for_budget": urls_rejected_for_budget,
        "pages_discovered": total_discovered_count,
        "pages_sampled": sum(1 for p in page_artifacts if not p.get("is_soft_blocked")),
        "pages_fetched": len(page_artifacts),
        "pages_failed": sum(1 for p in pages_skipped if p.get("reason", "").startswith("http_status_5") or p.get("reason") in ("fetch_failed", "timeout", "network_failure")),
        "pages_skipped": pages_skipped,
        "robots_blocked": sum(1 for p in pages_skipped if p.get("reason") == "robots_disallowed"),
        "browser_pages": browser_pages_count,
        "urls_rendered": browser_pages_count,
        "render_escalations": sum(1 for p in page_artifacts if p.get("render_escalated")),
        "render_escalation_reasons": list(set(p.get("render_reason") for p in page_artifacts if p.get("render_reason"))),
        "max_depth": MAX_DEPTH,
        "max_depth_reached": max_depth_reached,
        "max_pages": safe_max_pages,
        "crawl_completed": stopping_condition in ("source_exhaustion", "page_budget_exhausted"),
        "budget_exhausted": stopping_condition in ("page_budget_exhausted", "runtime_budget_exhausted"),
        "stop_reason": stopping_condition,
        "crawl_stop_reason": stopping_condition,
        "stopping_condition": stopping_condition,
        "runtime_budget_seconds": int(global_timeout),
        "runtime_elapsed_seconds": elapsed_seconds,
        "runtime_budget_exhausted": runtime_exhausted_flag,
        "sitemap": sitemap_meta,
        "pages_inspected": pages_inspected,
        "budget": {
            "max_pages": safe_max_pages,
            "pages_fetched": len(page_artifacts),
            "max_bytes_per_page": MAX_RESPONSE_SIZE,
            "max_browser_pages": MAX_BROWSER_PAGES,
            "runtime_budget_seconds": int(global_timeout),
        },
    }

    return build_final_report(
        urlparse(final_url).netloc,
        audited_at,
        raw_findings,
        enhanced=enhanced,
        page_artifacts=page_artifacts,
        coverage_data=coverage_data,
    )


def build_final_report(site, audited_at, raw_findings, enhanced=False, page_artifacts=None, coverage_data=None):
    """
    Aggregates findings, deduplicates by semantic composite key (Requirement 15),
    normalizes severity, enriches with rules/priorities, and constructs final report.
    """
    unique = {}
    for finding in raw_findings:
        evidence = str(finding.get("evidence", "")).strip()
        title = str(finding.get("title", "")).strip()
        if not evidence or not title:
            continue
        rule_id = str(finding.get("rule_id") or "").strip()
        source_url = str(finding.get("source_url") or "").strip()
        
        # Populate specific page context for finding enrichment
        # Look up the PageProfile for this source_url
        page_role = finding.get("page_role")
        page_intent = finding.get("page_intent")
        
        if page_artifacts and (not page_role or page_role == "general" or not page_intent):
            for p in page_artifacts:
                if p.get("final_url") == source_url or p.get("url") == source_url:
                    page_role = page_role if page_role and page_role != "general" else p.get("page_role", "general")
                    page_intent = page_intent or p.get("page_intent", "unknown")
                    break
                    
        finding["page_role"] = page_role or "general"
        finding["page_intent"] = page_intent or "unknown"

        # Semantic composite key: rule_id/title + URL set + evidence signature (Requirement 15 & P1-4)
        affected_urls = finding.get("affected_urls", [])
        if source_url and source_url not in affected_urls:
            affected_urls = [source_url] + affected_urls
        url_tuple = tuple(sorted(list(set(affected_urls))))
        norm_evidence = re.sub(r"\s+", " ", str(evidence).lower().strip())
        
        if rule_id:
            dedup_key = (rule_id, url_tuple, norm_evidence)
        else:
            norm_title = re.sub(r"\s+", " ", title.lower().strip())
            dedup_key = (norm_title, url_tuple, norm_evidence)

        severity = str(finding.get("severity", "medium")).lower()
        if severity not in {"critical", "high", "medium"}:
            severity = "medium"

        SEV_ORDER = {"critical": 3, "high": 2, "medium": 1}
        if dedup_key in unique:
            existing = unique[dedup_key]
            # Changing severity does not create a duplicate; preserve higher severity
            if SEV_ORDER.get(severity, 1) > SEV_ORDER.get(existing["severity"], 1):
                existing["severity"] = severity
                existing["raw"]["severity"] = severity
        else:
            unique[dedup_key] = {
                "title": title,
                "severity": severity,
                "evidence": evidence,
                "suggested_action": finding.get("suggested_action", {}),
                "raw": finding,
            }

    findings = []
    analysis_status = []
    summary = {"total_findings": 0, "critical": 0, "high": 0, "medium": 0}
    context = {
        "host": site,
        "url": f"https://{site}",
        "audited_at": audited_at,
    }

    for index, item in enumerate(unique.values(), 1):
        severity = item["severity"]
        action = item["suggested_action"] if isinstance(item["suggested_action"], dict) else {}
        base_finding = {
            "id": f"F-{index:03d}",
            "title": item["title"],
            "severity": severity,
            "evidence": item["evidence"],
            "suggested_action": {
                "summary": str(action.get("summary", "Review the evidence and address the underlying issue.")),
                "priority": str(action.get("priority", severity)),
            },
        }

        if enhanced:
            if item["raw"].get("source_url"):
                base_finding["source_url"] = item["raw"]["source_url"]
            if item["raw"].get("affected_urls"):
                base_finding["affected_urls"] = item["raw"]["affected_urls"]
                
            context_for_finding = dict(context)
            # P0-1: Use the explicit source_url of the finding, do not default to site root for subpage findings
            context_for_finding["url"] = item["raw"].get("source_url", context["url"])
            
            # P0-2: Use the explicit page_role/page_intent attached to the finding
            context_for_finding["page_role"] = item["raw"].get("page_role", "general")
            context_for_finding["page_intent"] = item["raw"].get("page_intent", "unknown")
            
            enriched = rules_module.enrich_finding(item["raw"], context_for_finding)
            base_finding["rule_id"] = enriched["rule_id"]
            base_finding["root_cause"] = enriched["root_cause"]
            base_finding["expected_mechanism"] = enriched["expected_mechanism"]
            base_finding["impact"] = enriched["impact"]
            base_finding["effort"] = enriched["effort"]
            base_finding["target_persona"] = enriched["target_persona"]
            base_finding["confidence"] = enriched["confidence"]
            base_finding["remediation_id"] = enriched["remediation_id"]
            base_finding["priority_score"] = enriched["priority_score"]
            base_finding["provenance"] = enriched["provenance"]
            if "implementation" in enriched:
                base_finding["implementation"] = enriched["implementation"]

        rule_id = item["raw"].get("rule_id", "")
        if rule_id == "CR-DETECTOR-INCOMPLETE-001":
            analysis_status.append(base_finding)
        else:
            findings.append(base_finding)
            summary[severity] += 1
            summary["total_findings"] += 1

    if enhanced:
        findings.sort(key=lambda f: f.get("priority_score", 0), reverse=True)
        for idx, f in enumerate(findings, 1):
            f["id"] = f"F-{idx:03d}"

    report = {
        "site": site,
        "audited_at": audited_at,
        "summary": summary,
        "analysis_status": analysis_status,
        "findings": findings,
    }

    if enhanced:
        arts = page_artifacts or []
        proactive = rules_module.generate_proactive_recommendations(arts, context)
        report["proactive_recommendations"] = proactive

        cov = coverage_data or {}
        report["evidence_coverage"] = {
            "pages_inspected": cov.get("pages_inspected", []),
            "pages_skipped": cov.get("pages_skipped", []),
            "budget": cov.get("budget", {"max_pages": DEFAULT_MAX_PAGES, "pages_fetched": len(arts), "max_bytes_per_page": MAX_RESPONSE_SIZE, "runtime_budget_seconds": int(cov.get("runtime_budget_seconds", DEFAULT_GLOBAL_TIMEOUT))}),
            "discovery_stopping_condition": cov.get("stopping_condition", "single_page_audit"),
            "evidence_summary": {
                "measured_findings": sum(1 for f in findings if f.get("confidence") == "measured"),
                "inferred_findings": sum(1 for f in findings if f.get("confidence") == "inferred"),
                "uncertain_findings": sum(1 for f in findings if f.get("confidence") == "uncertain"),
            },
        }
        report["coverage"] = {
            "requested_url": cov.get("requested_url", f"https://{site}"),
            "requested_page_budget": cov.get("requested_page_budget", DEFAULT_MAX_PAGES),
            "urls_seen_from_links": cov.get("urls_seen_from_links", 0),
            "urls_seen_from_sitemap": cov.get("urls_seen_from_sitemap", 0),
            "urls_discovered_total": cov.get("urls_discovered_total", cov.get("urls_discovered", len(arts))),
            "urls_discovered": cov.get("urls_discovered", len(arts) or 1),
            "urls_enqueued": cov.get("urls_enqueued", len(arts)),
            "urls_selected": cov.get("urls_selected", len(arts)),
            "urls_fetched": cov.get("urls_fetched", len(arts)),
            "urls_failed": cov.get("urls_failed", 0),
            "urls_skipped": len(cov.get("pages_skipped", [])),
            "urls_blocked_by_robots": cov.get("urls_blocked_by_robots", 0),
            "urls_rejected_for_scope": cov.get("urls_rejected_for_scope", 0),
            "urls_rejected_for_ssrf": cov.get("urls_rejected_for_ssrf", 0),
            "urls_rejected_as_trap": cov.get("urls_rejected_as_trap", 0),
            "urls_rejected_as_duplicate": cov.get("urls_rejected_as_duplicate", 0),
            "urls_rejected_for_budget": cov.get("urls_rejected_for_budget", 0),
            "pages_discovered": cov.get("pages_discovered", len(arts)),
            "pages_sampled": cov.get("pages_sampled", len(arts)),
            "pages_fetched": cov.get("pages_fetched", len(arts)),
            "pages_failed": cov.get("pages_failed", 0),
            "pages_skipped": len(cov.get("pages_skipped", [])),
            "robots_blocked": cov.get("robots_blocked", 0),
            "browser_pages": cov.get("browser_pages", 0),
            "max_depth": cov.get("max_depth", MAX_DEPTH),
            "max_depth_reached": cov.get("max_depth_reached", 0),
            "max_pages": cov.get("max_pages", DEFAULT_MAX_PAGES),
            "crawl_completed": cov.get("crawl_completed", True),
            "budget_exhausted": cov.get("budget_exhausted", False),
            "stop_reason": cov.get("stop_reason", "source_exhaustion"),
            "crawl_stop_reason": cov.get("crawl_stop_reason", "source_exhaustion"),
            "stopping_condition": cov.get("stopping_condition", "source_exhaustion"),
            "runtime_budget_seconds": cov.get("runtime_budget_seconds", int(DEFAULT_GLOBAL_TIMEOUT)),
            "runtime_elapsed_seconds": cov.get("runtime_elapsed_seconds", 0.0),
            "runtime_budget_exhausted": cov.get("runtime_budget_exhausted", False),
            "sitemap": cov.get("sitemap", {"attempted": False}),
        }

        # Inconclusive Readiness for insufficient coverage (Component 6)
        zero_coverage = False
        if cov.get("stopping_condition") in ("robots_blocked", "redirect_robots_blocked"):
            zero_coverage = True
        elif len(arts) == 0:
            zero_coverage = True
        elif all(p.get("extraction_uncertain") or p.get("status_code", 0) != 200 for p in arts):
            zero_coverage = True

        if zero_coverage:
            band = "Inconclusive"
            formula_explanation = "Audit could not meaningfully inspect site content because crawler permissions could not be verified or content was inaccessible; readiness is inconclusive."
        else:
            crit = summary["critical"]
            hi = summary["high"]
            if crit == 0 and hi <= 1:
                band = "Strong"
            elif crit == 0 and hi <= 3:
                band = "Developing"
            else:
                band = "Needs Work"
            formula_explanation = "Band derived deterministically from severity counts: Strong (critical=0, high<=1), Developing (critical=0, high<=3), Needs Work (critical>0 or high>3)."

        report["readiness_band"] = {
            "band": band,
            "formula_explanation": formula_explanation,
            "disclaimer": "This is a deterministic heuristic readiness classification based on observed findings in the sampled pages, not an external search engine benchmark or guarantee.",
        }

        tot = summary["total_findings"]
        crit_count = summary["critical"]
        high_count = summary["high"]
        med_count = summary["medium"]
        sampled_count = len(arts) or 1
        depth_reached = cov.get("max_depth_reached", 0)

        if tot == 0:
            exec_summary = (
                f"The automated audit sampled {sampled_count} page(s) across up to depth {depth_reached} on {site}. "
                f"The sampled pages did not produce high-severity findings under the current deterministic checks."
            )
        else:
            top_titles = [f["title"] for f in findings[:3]]
            top_joined = "; ".join(top_titles)
            exec_summary = (
                f"The automated audit sampled {sampled_count} page(s) across up to depth {depth_reached} on {site} "
                f"and identified {tot} potential optimization area(s) in the audited sample "
                f"({crit_count} critical, {high_count} high, {med_count} medium). "
                f"Primary mechanisms requiring attention include: {top_joined}."
            )
        report["executive_summary"] = exec_summary

    return report


def _main():
    if "--help" in sys.argv or "-h" in sys.argv:
        help_text = (
            "Usage: python run_audit.py <URL> [OPTIONS]\n\n"
            "Brand AI-Readiness Audit Orchestrator CLI\n\n"
            "Arguments:\n"
            "  URL                  Target HTTP/HTTPS website URL to audit\n\n"
            "Options:\n"
            "  --max-pages <N>      Maximum pages to crawl and sample (default: 20, max: 50)\n"
            "  --floor              Run minimal baseline schema check without full heuristics\n"
            "  --help, -h           Show this help message and exit\n"
        )
        print(help_text)
        return 0

    if len(sys.argv) < 2:
        print(json.dumps({"error": "Missing target URL"}), file=sys.stderr)
        return 1

    target_url = sys.argv[1]
    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        print(json.dumps({"error": f"Invalid URL: {target_url}"}), file=sys.stderr)
        return 1

    enhanced = "--floor" not in sys.argv
    max_pages = DEFAULT_MAX_PAGES

    # Parse optional --max-pages flag
    if "--max-pages" in sys.argv:
        try:
            idx = sys.argv.index("--max-pages")
            if idx + 1 < len(sys.argv):
                max_pages = int(sys.argv[idx + 1])
        except (ValueError, IndexError):
            pass

    try:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            report = run_pipeline(target_url, enhanced=enhanced, max_pages=max_pages)
        if buffer.getvalue():
            print(buffer.getvalue(), file=sys.stderr, end="")
        print(json.dumps(report, indent=2, sort_keys=False))
        return 0
    except Exception as exc:
        print(json.dumps({"error": f"Pipeline failure: {exc}"}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(_main())
