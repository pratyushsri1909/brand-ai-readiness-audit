import os
import re
import urllib.parse
import xml.etree.ElementTree as ET
from html.parser import HTMLParser


_COMMON_MULTI_LABEL_SUFFIXES = frozenset({"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.in", "org.in", "co.jp", "co.nz", "com.br", "com.cn", "com.sg", "com.tr"})

def _registrable_domain(hostname):
    host = (hostname or "").lower().rstrip(".").strip("[]")
    if not host:
        return ""
    labels = [p for p in host.split(".") if p]
    if len(labels) <= 2:
        return host
    suffix2 = ".".join(labels[-2:])
    if suffix2 in _COMMON_MULTI_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])

def host_in_scope(candidate_host, target_host):
    def _host(value):
        value = str(value or "").strip()
        if "://" not in value:
            value = "//" + value
        try:
            return (urllib.parse.urlparse(value).hostname or "").lower().rstrip(".")
        except Exception:
            return ""
    c = _host(candidate_host)
    t = _host(target_host)
    if not c or not t:
        return False
    t = t[4:] if t.startswith("www.") else t
    base = _registrable_domain(t)
    return _registrable_domain(c) == base and (c == t or c == base or c.endswith("." + base))


TRACKING_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "gclid", "fbclid", "msclkid", "mc_cid", "mc_eid", "ref", "source",
    "_ga", "_gl", "yclid", "fb_action_ids", "fb_action_types"
}

NON_HTML_EXTENSIONS = frozenset({
    ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".mp4", ".mp3", ".avi", ".mov", ".wmv", ".flv", ".webm",
    ".zip", ".gz", ".tar", ".tgz", ".bz2", ".7z", ".rar",
    ".exe", ".dmg", ".pkg", ".deb", ".rpm", ".apk", ".iso",
    ".css", ".js", ".mjs", ".map", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".xml", ".json", ".csv", ".tsv", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx"
})

ROLE_SIGNALS = {
    "about": {
        "path_patterns": [r"/about(?:-us)?/?", r"/our-story/?", r"/company/?", r"/who-we-are/?", r"/ueber-uns/?", r"/a-propos/?"],
        "text_patterns": [
            r"\babout\b", r"\babout us\b", r"\bour story\b", r"\bcompany\b", r"\bwho we are\b", r"\bour mission\b",
            r"\bsobre nosotros\b", r"\bquienes somos\b", r"\ba propos\b", r"\bqui sommes nous\b",
            r"\bueber uns\b", r"\büber uns\b", r"\bchi siamo\b", r"\bsobre nos\b", r"\bquem somos\b"
        ],
    },
    "contact": {
        "path_patterns": [r"/contact(?:-us)?/?", r"/get-in-touch/?", r"/reach-us/?", r"/kontakt/?"],
        "text_patterns": [
            r"\bcontact\b", r"\bcontact us\b", r"\bget in touch\b", r"\breach us\b", r"\bsupport\b",
            r"\bcontacto\b", r"\bcontactanos\b", r"\bcontactez nous\b", r"\bkontakt\b", r"\bcontatti\b", r"\bfale conosco\b"
        ],
    },
    "pricing": {
        "path_patterns": [r"/pricing/?", r"/plans?/?", r"/rates?/?", r"/tiers-and-investment/?", r"/tarifs?/?", r"/preise/?"],
        "text_patterns": [
            r"\bpricing\b", r"\bplans\b", r"\brates\b", r"\bpackages\b", r"\btiers\b", r"\binvestment\b",
            r"\bprecios\b", r"\btarifas\b", r"\btarifs\b", r"\bprix\b", r"\bpreise\b", r"\bprezzi\b", r"\bprecos\b"
        ],
    },
    "product": {
        "path_patterns": [r"/products?/[^/]+", r"/item/[^/]+", r"/p/[^/]+", r"/produit/[^/]+", r"/produkt/[^/]+"],
        "text_patterns": [
            r"\bproduct\b", r"\bbuy now\b", r"\bfeatures\b", r"\bitem\b", r"\border now\b",
            r"\bproducto\b", r"\bcomprar\b", r"\bproduit\b", r"\bacheter\b", r"\bprodukt\b", r"\bkaufen\b"
        ],
    },
    "service": {
        "path_patterns": [r"/services?/[^/]+", r"/solutions?/[^/]+", r"/offerings?/[^/]+", r"/what-we-offer/?"],
        "text_patterns": [
            r"\bservices?\b", r"\bsolutions?\b", r"\bwhat we offer\b", r"\bconsulting\b", r"\bcapabilities\b",
            r"\bservicios\b", r"\bsoluciones\b", r"\bleistungen\b", r"\bdienstleistungen\b", r"\bservizi\b"
        ],
    },
    "category": {
        "path_patterns": [r"/products?/?$", r"/services?/?$", r"/shop/?$", r"/catalog/?$", r"/collections?/?", r"/boutique/?"],
        "text_patterns": [
            r"\bshop\b", r"\bproducts\b", r"\bservices\b", r"\bcatalog\b", r"\bcollections\b", r"\bstore\b",
            r"\btienda\b", r"\bboutique\b"
        ],
    },
    "article": {
        "path_patterns": [r"/blog/[^/]+", r"/news/[^/]+", r"/articles?/[^/]+", r"/insights?/[^/]+", r"/posts?/[^/]+"],
        "text_patterns": [
            r"\bblog\b", r"\bnews\b", r"\barticles?\b", r"\bread more\b", r"\binsights\b",
            r"\bnoticias\b", r"\bactualites\b", r"\bnachrichten\b"
        ],
    },
    "documentation": {
        "path_patterns": [r"/docs?/[^/]*", r"/documentation/[^/]*", r"/guides?/[^/]*", r"/api(?:-reference)?/?"],
        "text_patterns": [
            r"\bdocumentation\b", r"\bdocs\b", r"\bguide\b", r"\bapi\b", r"\bmanual\b", r"\breference\b",
            r"\bdocumentacion\b", r"\banleitung\b"
        ],
    },
    "case-study": {
        "path_patterns": [r"/case-studies/[^/]*", r"/customer-stories/[^/]*", r"/success-stories/[^/]*"],
        "text_patterns": [
            r"\bcase stud(?:y|ies)\b", r"\bcustomer stories\b", r"\bsuccess stories\b", r"\bcasos de exito\b"
        ],
    },
    "faq": {
        "path_patterns": [r"/faq/?", r"/help/?", r"/support/?", r"/questions?/?"],
        "text_patterns": [
            r"\bfaq\b", r"\bhelp\b", r"\bsupport\b", r"\bfrequently asked\b", r"\bpreguntas frecuentes\b"
        ],
    },
}

LOW_VALUE_ANCHOR_PATTERNS = [
    r"\bprivacy(?: policy)?\b",
    r"\bterms(?: of (?:service|use))?\b",
    r"\bcookie(?: settings| policy)?\b",
    r"\blogin\b",
    r"\bsign (?:in|up)\b",
    r"\bforgot password\b",
    r"\bcart\b",
    r"\bcheckout\b",
    r"\baccessibility\b",
    r"\bdisclaimer\b",
    r"\blegal\b",
]

HIGH_VALUE_ANCHOR_PATTERNS = [
    r"\babout(?: us)?\b",
    r"\bproducts?\b",
    r"\bservices?\b",
    r"\bpricing\b",
    r"\bplans\b",
    r"\btiers\b",
    r"\bcontact(?: us)?\b",
    r"\bfeatures\b",
    r"\bsolutions\b",
    r"\bdocumentation\b",
    r"\bdocs\b",
    r"\bcase studies\b",
    r"\bcompany\b",
    r"\bprecios\b",
    r"\btarifs\b",
    r"\bpreise\b",
]


class LinkExtractor(HTMLParser):
    def __init__(self, base_url=""):
        super().__init__()
        self.base_url = base_url
        self.links = []
        self._current_href = None
        self._current_text = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            d = dict(attrs)
            href = (d.get("href") or "").strip()
            if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                self._current_href = href
                self._current_text = []

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._current_href:
            text = " ".join(self._current_text).strip()
            self.links.append((self._current_href, text))
            self._current_href = None
            self._current_text = []

    def handle_data(self, data):
        if self._current_href:
            self._current_text.append(data.strip())


def normalize_url(raw_url, base_url=""):
    """
    Normalizes URL: resolves relative against base_url, lowercases scheme & host,
    strips default port (80/443), strips fragments, collapses multiple slashes,
    and removes marketing/tracking parameters while preserving functional query parameters.
    """
    if not raw_url:
        return ""
    if base_url:
        resolved = urllib.parse.urljoin(base_url, raw_url)
    else:
        resolved = raw_url

    parsed = urllib.parse.urlparse(resolved)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        return ""

    netloc = parsed.netloc.lower()
    if netloc.endswith(":80") and parsed.scheme == "http":
        netloc = netloc[:-3]
    elif netloc.endswith(":443") and parsed.scheme == "https":
        netloc = netloc[:-4]

    path = parsed.path or "/"
    # Clean up double slashes in path
    path = re.sub(r"/{2,}", "/", path)

    # Strip tracking parameters
    if parsed.query:
        query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        filtered_pairs = [(k, v) for k, v in query_pairs if k.lower() not in TRACKING_PARAMS]
        clean_query = urllib.parse.urlencode(filtered_pairs)
    else:
        clean_query = ""

    return urllib.parse.urlunparse((parsed.scheme, netloc, path, "", clean_query, ""))


def should_visit_url(raw_url, base_url="", visited_set=None, depth=0, max_depth=3, target_host=None):
    """
    Layered predicate check for candidate crawl URLs:
      1. Scheme validation (http/https only)
      2. Host validation (same host / domain scope)
      3. Non-HTML file extension filtering (.pdf, .png, etc.)
      4. Crawl trap prevention (parameter explosion, search/filter endpoints, pagination traps, loop paths)
      5. Depth ceiling check (depth <= max_depth)
      6. Duplicate check (not in visited_set)

    Returns (should_visit: bool, reason: str, normalized_url: str)
    """
    if not raw_url:
        return False, "invalid_or_unsupported_url", ""

    # Check raw scheme before resolving/normalizing
    parsed_raw = urllib.parse.urlparse(raw_url)
    if parsed_raw.scheme and parsed_raw.scheme.lower() not in ("http", "https"):
        return False, "unsupported_scheme", raw_url

    norm = normalize_url(raw_url, base_url=base_url)
    if not norm:
        return False, "invalid_or_unsupported_url", ""

    parsed = urllib.parse.urlparse(norm)
    if parsed.scheme not in ("http", "https"):
        return False, "unsupported_scheme", norm

    # Host check
    if not target_host and base_url:
        target_host = urllib.parse.urlparse(normalize_url(base_url)).netloc.lower()
    if target_host and not host_in_scope(parsed.hostname, target_host):
        return False, "external_domain", norm

    # File extension filtering
    path_lower = parsed.path.lower()
    root_ext = os.path.splitext(path_lower)[1]
    if root_ext in NON_HTML_EXTENSIONS:
        return False, f"non_html_extension_{root_ext}", norm

    # Depth ceiling
    if depth > max_depth:
        return False, f"max_depth_exceeded_{depth}", norm

    # Crawl traps:
    # 1. Parameter explosion (> 4 query parameters)
    if parsed.query:
        qp = urllib.parse.parse_qsl(parsed.query)
        if len(qp) > 4:
            return False, "query_parameter_explosion_trap", norm

    # 2. Search / filter endpoints
    if re.search(r"/(?:search|filter|find|query)(?:/|\?|$)", path_lower):
        return False, "search_or_filter_trap", norm

    # 3. Pagination limits (prevent infinite page=1000 crawling)
    if parsed.query:
        for k, v in urllib.parse.parse_qsl(parsed.query):
            if k.lower() in ("page", "p", "pg", "offset") and v.isdigit():
                if int(v) > 10:
                    return False, "pagination_depth_trap", norm

    # 4. Repeating path loops (e.g. /a/b/a/b/a/b)
    segments = [s for s in path_lower.split("/") if s]
    if len(segments) >= 4 and len(set(segments)) <= len(segments) // 2:
        return False, "repeating_path_segment_trap", norm

    # 5. Calendar / date traps (e.g. /2024/05/01/ or /calendar/)
    if re.search(r"/\d{4}/\d{2}/\d{2}/", path_lower) or "/calendar/" in path_lower:
        return False, "calendar_date_trap", norm

    # Duplicate check
    if visited_set is not None and norm in visited_set:
        return False, "already_visited", norm

    return True, "valid_candidate", norm


def score_url_priority(url, link_text="", inferred_role=None, from_sitemap=False, depth=0):
    """
    Deterministic semantic priority score for candidate queue:
      - Higher score for important page roles (About, Product, Contact, Pricing, FAQ, Article)
      - Bonus for sitemap discovery
      - Bonus for high-value anchor text
      - Penalty for low-value anchors (legal, login, cart, cookie)
      - Modest penalty for crawl depth
    """
    score = 10.0
    text_lower = (link_text or "").lower()

    if inferred_role == "homepage":
        score += 20.0
    elif inferred_role == "about":
        score += 15.0
    elif inferred_role == "product":
        score += 14.0
    elif inferred_role == "contact":
        score += 13.0
    elif inferred_role == "pricing":
        score += 12.0
    elif inferred_role == "faq":
        score += 11.0
    elif inferred_role == "category":
        score += 10.0
    elif inferred_role == "article":
        score += 8.0

    if from_sitemap:
        score += 5.0

    # High-value anchor terms
    for pat in HIGH_VALUE_ANCHOR_PATTERNS:
        if re.search(pat, text_lower):
            score += 4.0
            break

    # Low-value anchor terms
    for pat in LOW_VALUE_ANCHOR_PATTERNS:
        if re.search(pat, text_lower):
            score -= 8.0
            break

    # Depth penalty
    score -= 2.0 * depth

    return max(score, 0.1)


def extract_links_from_html(html, base_url=""):
    """Extracts and returns list of (href, text) from HTML."""
    if not html:
        return []
    extractor = LinkExtractor(base_url=base_url)
    extractor.feed(html)
    return extractor.links


def extract_sitemap_urls_from_robots(robots_content):
    """Finds all Sitemap: URLs declared in robots.txt."""
    sitemaps = []
    if not robots_content:
        return sitemaps
    for line in robots_content.splitlines():
        line = line.strip()
        if line.lower().startswith("sitemap:"):
            parts = line.split(":", 1)
            if len(parts) == 2 and parts[1].strip():
                sitemaps.append(parts[1].strip())
    return sitemaps


def parse_sitemap_xml(xml_content):
    """
    Parses XML sitemap string using stdlib xml.etree.ElementTree.
    Returns (urls_list, child_sitemaps_list).
    """
    urls = []
    child_sitemaps = []
    if not xml_content or not xml_content.strip():
        return urls, child_sitemaps

    try:
        root = ET.fromstring(xml_content)
    except Exception:
        return urls, child_sitemaps

    # Strip XML namespace if present
    tag = root.tag
    ns = ""
    if tag.startswith("{"):
        ns = tag.split("}")[0] + "}"

    if tag == f"{ns}sitemapindex":
        for sm in root.findall(f"{ns}sitemap"):
            loc = sm.find(f"{ns}loc")
            if loc is not None and loc.text and loc.text.strip():
                child_sitemaps.append(loc.text.strip())
    elif tag == f"{ns}urlset":
        for u in root.findall(f"{ns}url"):
            loc = u.find(f"{ns}loc")
            if loc is not None and loc.text and loc.text.strip():
                urls.append(loc.text.strip())

    return urls, child_sitemaps


def classify_url_role(url, link_text=""):
    """
    Deterministic rule-based role classification prioritizing anchor text over URL path.
    Returns (inferred_role, reason). Leaves role as None if confidence is low.
    """
    parsed = urllib.parse.urlparse(url)
    path = parsed.path.lower()
    text = (link_text or "").lower().strip()

    if path in ("", "/"):
        return "homepage", "Audited root path"

    # 1. Semantic anchor text (strongest contextual signal)
    if text:
        for role, rules in ROLE_SIGNALS.items():
            for tpat in rules.get("text_patterns", []):
                if re.search(tpat, text):
                    return role, f"Anchor text matches {role} term '{tpat}'"

    # 2. Path patterns as weak secondary hint
    for role, rules in ROLE_SIGNALS.items():
        for pat in rules.get("path_patterns", []):
            if re.search(pat, path):
                return role, f"URL path matches {role} pattern '{pat}'"

    return None, "No definitive role heuristic matched within budget"


def build_page_plan(candidate_links, root_url, budget=5):
    """
    Selects up to `budget` representative pages across diverse roles (Homepage, About,
    Product/Service, Category, Contact, Article, Pricing, FAQ).
    Returns (page_plan, stopping_condition).
    """
    root_norm = normalize_url(root_url)
    root_parsed = urllib.parse.urlparse(root_norm)
    target_host = root_parsed.netloc

    plan = []
    # 1. Root page is always slot #1
    plan.append({
        "url": root_norm,
        "inferred_role": "homepage",
        "reason_selected": "Audited domain entrypoint",
    })
    selected_urls = {root_norm}
    filled_roles = {"homepage"}

    # Categorize candidates
    categorized = []
    for href, text in candidate_links:
        norm = normalize_url(href, base_url=root_norm)
        if not norm or norm in selected_urls:
            continue
        parsed = urllib.parse.urlparse(norm)
        if not host_in_scope(parsed.hostname, target_host):
            continue
        role, reason = classify_url_role(norm, text)
        categorized.append((norm, role, reason))

    # Priority role filling
    target_role_sequence = ["about", "contact", "product", "pricing", "faq", "service", "category", "article", "documentation", "case-study"]

    for desired_role in target_role_sequence:
        if len(plan) >= budget:
            break
        for norm, role, reason in categorized:
            if role == desired_role and norm not in selected_urls:
                plan.append({
                    "url": norm,
                    "inferred_role": role,
                    "reason_selected": reason,
                })
                selected_urls.add(norm)
                filled_roles.add(role)
                break

    # If budget remains, take unclassified or additional candidate pages
    if len(plan) < budget:
        for norm, role, reason in categorized:
            if norm not in selected_urls:
                plan.append({
                    "url": norm,
                    "inferred_role": role or "unknown",
                    "reason_selected": reason or "Representative internal link",
                })
                selected_urls.add(norm)
                if len(plan) >= budget:
                    break

    stopping_condition = "budget_reached" if len(plan) >= budget else "source_exhaustion"
    return plan, stopping_condition


def audit(artifact):
    """
    Standard detector entrypoint for site-discovery-audit.
    Inputs: artifact containing url, html, robots_content, optional sitemap_xml.
    """
    status = artifact.get("status_code", 200)
    fetch_mode = artifact.get("fetch_mode", "http_static")
    if (status is not None and status != 200 and status != 0) or fetch_mode == "unsupported_content_type":
        return {
            "findings": [],
            "page_plan": [],
            "stopping_condition": "fetch_failed",
            "candidate_urls_count": 0,
            "sitemap_declared": False,
        }

    url = artifact.get("url", "")
    html = artifact.get("html", "") or ""
    robots_content = artifact.get("robots_content", "") or ""
    sitemap_xml = artifact.get("sitemap_xml")
    budget = artifact.get("page_budget", 5)

    findings = []
    candidate_links = []
    sitemap_found = False

    # 1. Discover sitemap declarations
    declared_sitemaps = extract_sitemap_urls_from_robots(robots_content)
    if declared_sitemaps:
        sitemap_found = True

    if sitemap_xml:
        sitemap_urls, child_sms = parse_sitemap_xml(sitemap_xml)
        for s_url in sitemap_urls:
            candidate_links.append((s_url, ""))
        if sitemap_urls:
            sitemap_found = True

    # 2. Extract internal links from HTML
    extractor = LinkExtractor(base_url=url)
    extractor.feed(html)
    for href, text in extractor.links:
        candidate_links.append((href, text))

    if not sitemap_found and not declared_sitemaps:
        findings.append({
            "rule_id": "DISC-SITEMAP-MISSING-001",
            "title": "Missing or Inaccessible XML Sitemap",
            "severity": "medium",
            "evidence": "No XML Sitemap directive was declared in robots.txt and no sitemap content was discovered.",
            "suggested_action": {
                "summary": "Publish a standards-compliant XML sitemap and declare its location in robots.txt for machine discovery.",
                "priority": "medium",
            },
        })

    # 3. Build bounded page plan
    page_plan, stopping_condition = build_page_plan(candidate_links, url, budget=budget)

    return {
        "findings": findings,
        "page_plan": page_plan,
        "stopping_condition": stopping_condition,
        "candidate_urls_count": len(candidate_links),
        "sitemap_declared": bool(declared_sitemaps),
    }
