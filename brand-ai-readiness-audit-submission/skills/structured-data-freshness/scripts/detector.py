import json
import re
import email.utils
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urlparse

# Default reference audit date for deterministic offline evaluation
DEFAULT_AUDIT_DATE = datetime(2026, 9, 5, tzinfo=timezone.utc)
DEFAULT_STALE_THRESHOLD_DAYS = 548  # 18 months configurable default


class ScriptParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.blocks = []
        self.current = None
        self.current_type = None
        self.in_script = False

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "script":
            return
        attrs_dict = {k.lower(): v for k, v in attrs}
        self.in_script = True
        self.current = []
        self.current_type = (attrs_dict.get("type") or "").lower()

    def handle_data(self, data):
        if self.in_script and self.current is not None:
            self.current.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "script" and self.in_script:
            if self.current_type == "application/ld+json":
                self.blocks.append("".join(self.current))
            self.current = None
            self.current_type = None
            self.in_script = False


def extract_json_ld_objects(html_content):
    parser = ScriptParser()
    parser.feed(html_content or "")
    objects = []
    malformed = 0
    for block in parser.blocks:
        try:
            data = json.loads(block.strip())
        except (json.JSONDecodeError, TypeError):
            malformed += 1
            continue
        if isinstance(data, list):
            objects.extend(item for item in data if isinstance(item, dict))
        elif isinstance(data, dict):
            graph = data.get("@graph")
            if isinstance(graph, list):
                objects.extend(item for item in graph if isinstance(item, dict))
            else:
                objects.append(data)
        # JSON scalar roots are valid JSON but do not describe an entity; skip safely.
    return objects, malformed, len(parser.blocks)


def _types(objects):
    result = set()
    for obj in objects:
        value = obj.get("@type")
        if isinstance(value, str):
            result.add(value)
        elif isinstance(value, list):
            result.update(v for v in value if isinstance(v, str))
    return result


def _canonical(html):
    m = re.search(r'<link\b[^>]*rel=["\']canonical["\'][^>]*href=["\']([^"\']+)["\']', html or "", re.I)
    if not m:
        m = re.search(r'<link\b[^>]*href=["\']([^"\']+)["\'][^>]*rel=["\']canonical["\']', html or "", re.I)
    return m.group(1).strip() if m else ""


def _commerce_signals(html):
    text = re.sub(r"<[^>]+>", " ", html or " ").lower()
    price = bool(re.search(r"(?:[$€£₹]|usd|eur|gbp|inr)\s*[0-9][0-9,]*(?:\.\d+)?", text))
    cta = bool(re.search(r"\b(add\s+to\s+cart|buy\s+now|purchase|checkout)\b", text))
    inventory = bool(re.search(r"\b(in\s+stock|out\s+of\s+stock|sku|quantity)\b", text))
    product_context = bool(re.search(r"\b(product|item|variant|price|cart|shop)\b", text))
    return price, cta, inventory, product_context


def _has_product_entity(objects):
    """Return True only when page-local structured data declares Product/Offer."""
    for obj in objects:
        t = obj.get("@type")
        types = t if isinstance(t, list) else [t]
        if any(str(v).lower() in {"product", "offer"} for v in types if v):
            return True
    return False


def _page_is_transactional(artifact, html, price, cta, inventory, product_context):
    """Require page-local transactional/product intent before commerce-schema finding."""
    role = str(artifact.get("page_role") or artifact.get("inferred_role") or "").lower()
    intent = str(artifact.get("page_intent") or artifact.get("intent") or "").lower()
    informational_roles = {
        "faq", "contact", "about", "article", "blog", "news",
        "help", "support", "documentation", "docs", "general"
    }
    if role in informational_roles or intent in informational_roles:
        return False

    # Purchase vocabulary alone is not a transaction. Require an actual action
    # element (button/link) whose own label expresses purchase intent.
    action_element = False
    action_blocks = re.findall(
        r'<(?:button|a)\b[^>]*>(.*?)</(?:button|a)>', html or "", re.I | re.S
    )
    for block in action_blocks:
        label = re.sub(r"<[^>]+>", " ", block).strip().lower()
        if re.search(r"\b(add\s+to\s+cart|buy\s+now|purchase|checkout)\b", label):
            action_element = True
            break
    if not action_element:
        input_values = re.findall(r'<input\b[^>]*\bvalue=["\']([^"\']+)["\']', html or "", re.I)
        action_element = any(
            re.search(r"\b(add\s+to\s+cart|buy\s+now|purchase|checkout)\b", value, re.I)
            for value in input_values
        )

    strong_role = role in {"product", "store", "commerce", "shop"} or intent in {"product", "store", "commerce", "shop"}
    explicit_product_shape = bool(re.search(
        r"\b(product details|product information|model|variant|sku|in stock)\b",
        re.sub(r"<[^>]+>", " ", html or " "), re.I
    ))

    # A genuine product-shaped page needs a price + purchase action plus either
    # explicit product identity signals or a strong product/store role from the
    # shared crawler context.
    return bool(price and cta and action_element and (inventory or explicit_product_shape or product_context)
                and (strong_role or explicit_product_shape))


def parse_date(date_str):
    if not date_str or not isinstance(date_str, str):
        return None
    date_str = date_str.strip()
    try:
        clean_iso = date_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        pass
    try:
        dt = email.utils.parsedate_to_datetime(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        pass
    try:
        m = re.match(r"^(\d{4})-(\d{2})-(\d{2})$", date_str)
        if m:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=timezone.utc)
    except Exception:
        pass
    return None


def _check_non_text_facts(html):
    findings = []
    if not html:
        return findings

    # 1. Substantive images without alt text
    img_matches = re.finditer(r'<img\b([^>]*?)>', html, re.I)
    decorative_names = {"icon", "bullet", "arrow", "spacer", "pixel", "blank", "chevron", "spinner", "avatar", "logo"}
    substantive_names = {"chart", "graph", "diagram", "infographic", "pricing", "matrix", "table", "flowchart", "stats", "comparison"}

    for m in img_matches:
        attrs_str = m.group(1)
        src_m = re.search(r'src=["\']([^"\']+)["\']', attrs_str, re.I)
        src = src_m.group(1) if src_m else ""

        # Check for role=presentation or aria-hidden=true
        if re.search(r'role=["\'](?:presentation|none)["\']', attrs_str, re.I) or re.search(r'aria-hidden=["\']true["\']', attrs_str, re.I):
            continue

        # Check if alt attribute is present
        has_alt_attr = bool(re.search(r'\balt\s*=', attrs_str, re.I))
        alt_val_m = re.search(r'\balt=["\']([^"\']*)["\']', attrs_str, re.I)
        alt_val = alt_val_m.group(1).strip() if alt_val_m else ""

        # Explicit alt="" indicates intentionally decorative element
        if has_alt_attr and alt_val == "":
            continue

        src_lower = src.lower()
        is_substantive = any(sub in src_lower for sub in substantive_names)
        is_decorative = any(dec in src_lower for dec in decorative_names)

        if not has_alt_attr and not is_decorative:
            if is_substantive:
                findings.append({
                    "rule_id": "SD-NONTEXT-001",
                    "title": "Critical Information Locked in Image Without Accessible Text",
                    "severity": "high",
                    "evidence": f"Substantive visual element <img src='{src}'> has no alt attribute or transcript, locking potential visual facts away from machine readers.",
                    "suggested_action": {
                        "summary": "Provide comprehensive alt text and a nearby textual transcript for diagrams, infographics, and charts.",
                        "priority": "high",
                        "impact": "high",
                        "effort": "medium",
                        "target_persona": "content_writer",
                    },
                })
            elif "<article" in html.lower() or "<main" in html.lower():
                findings.append({
                    "rule_id": "SD-NONTEXT-001",
                    "title": "Content Image Missing Alt Text",
                    "severity": "medium",
                    "evidence": f"Image element <img src='{src}'> in content area lacks an alt text description.",
                    "suggested_action": {
                        "summary": "Add descriptive alt text describing the image content for AI extractors and accessibility.",
                        "priority": "medium",
                        "impact": "medium",
                        "effort": "easy",
                        "target_persona": "content_writer",
                    },
                })

    # 2. Canvas elements without text fallback
    canvas_matches = re.finditer(r'<canvas\b[^>]*>(.*?)</canvas>', html, re.I | re.S)
    for c in canvas_matches:
        inner = re.sub(r'<[^>]+>', ' ', c.group(1)).strip()
        if not inner:
            findings.append({
                "rule_id": "SD-NONTEXT-001",
                "title": "Information Locked in Canvas Without Text Fallback",
                "severity": "medium",
                "evidence": "Document contains an HTML <canvas> element without an accessible text fallback for machine readers.",
                "suggested_action": {
                    "summary": "Provide semantic text descriptions or data tables alongside dynamic canvas visualizations.",
                    "priority": "medium",
                    "impact": "medium",
                    "effort": "medium",
                    "target_persona": "developer",
                },
            })
            break

    # 3. SVG elements without accessible text description (Requirement 18)
    svg_matches = re.finditer(r'<svg\b([^>]*?)>(.*?)</svg>', html, re.I | re.S)
    for s in svg_matches:
        svg_attrs = s.group(1)
        svg_body = s.group(2)

        # Ignore decorative SVGs: aria-hidden="true", role="presentation", role="none"
        if re.search(r'aria-hidden=["\']true["\']', svg_attrs, re.I) or re.search(r'role=["\'](?:presentation|none)["\']', svg_attrs, re.I):
            continue

        has_title = bool(re.search(r'<title\b[^>]*>\s*(\S+.*?)\s*</title>', svg_body, re.I | re.S))
        has_desc = bool(re.search(r'<desc\b[^>]*>\s*(\S+.*?)\s*</desc>', svg_body, re.I | re.S))
        has_aria_label = bool(re.search(r'aria-label=["\']\s*(\S+.*?)\s*["\']', svg_attrs, re.I))
        has_aria_labelledby = bool(re.search(r'aria-labelledby=["\']\s*(\S+.*?)\s*["\']', svg_attrs, re.I))

        if not (has_title or has_desc or has_aria_label or has_aria_labelledby):
            has_shapes = bool(re.search(r'<(?:path|rect|circle|polygon|line|g)\b', svg_body, re.I))
            if has_shapes:
                findings.append({
                    "rule_id": "SD-NONTEXT-001",
                    "title": "SVG Element Lacks Accessible Description",
                    "severity": "medium",
                    "evidence": "Meaningful SVG graphic lacks an accessible description (<title>, <desc>, aria-label, or aria-labelledby) and is not marked aria-hidden='true'.",
                    "suggested_action": {
                        "summary": "Add a <title> element or aria-label to meaningful SVGs so AI search agents and screen readers can interpret the graphic content.",
                        "priority": "medium",
                        "impact": "medium",
                        "effort": "easy",
                        "target_persona": "developer",
                    },
                })
                break

    return findings


def audit(artifact):
    html = artifact.get("html", "") or ""
    url = artifact.get("url", "")
    headers = artifact.get("headers", {}) or {}
    fetch_mode = artifact.get("fetch_mode", "")
    status_code = artifact.get("status_code", 200)
    content_type = (artifact.get("content_type") or "").lower()

    # Requirement 6 & 13: For failed fetches or non-HTML pages, do not emit false absence findings
    if fetch_mode in ("unsupported_content_type", "fetch_failed", "blocked") or (status_code and status_code != 200):
        return {"findings": []}
    if content_type and not ("text/html" in content_type or "application/xhtml" in content_type):
        return {"findings": []}

    # Generic extraction uncertainty guard: when static extraction was unreliable
    # (e.g. unresolved SPA shell after failed/unavailable browser recovery),
    # absence of JSON-LD is not reliable evidence. Do not emit SD-MISSING-001.
    # Positive observations (valid JSON-LD found, malformed syntax in reliable HTML)
    # are still preserved.
    extraction_uncertain = artifact.get("extraction_uncertain", False)
    is_spa_shell = artifact.get("is_spa_shell", False)
    unreliable_extraction = extraction_uncertain or is_spa_shell

    findings = []
    objects, malformed, block_count = extract_json_ld_objects(html)
    types = _types(objects)

    if block_count == 0 and not unreliable_extraction:
        role = artifact.get("page_role", "general")
        intent = artifact.get("page_intent", "unknown")
        text_len = artifact.get("raw_text_length", 0)
        
        severity = "medium"
        if role in ("product", "service") or intent in ("product", "service"):
            severity = "high"
        elif role == "article" or intent == "article":
            severity = "high" if text_len > 1500 else "medium"
        elif role in ("about", "contact", "legal"):
            severity = "low"
        elif role == "homepage":
            severity = "medium"
            
        findings.append({
            "rule_id": "SD-MISSING-001",
            "title": "Missing JSON-LD Structured Data",
            "severity": severity,
            "evidence": f"No application/ld+json block was found in the initial HTML response for this {role} page.",
            "suggested_action": {
                "summary": "Add appropriate Schema.org JSON-LD for the page's primary entity and important facts.",
                "priority": severity,
                "impact": severity,
                "effort": "medium",
                "target_persona": "developer",
                "recommended_snippet": {
                    "language": "json",
                    "code": json.dumps({
                        "@context": "https://schema.org",
                        "@type": "WebSite",
                        "name": "YOUR_BRAND_NAME",
                        "url": "YOUR_CANONICAL_URL",
                    }, indent=2),
                },
            },
        })
    if malformed:
        findings.append({
            "rule_id": "SD-SYNTAX-001",
            "title": "Malformed JSON-LD Syntax",
            "severity": "high",
            "evidence": f"{malformed} of {block_count} JSON-LD block(s) failed strict JSON parsing; valid blocks were processed independently.",
            "suggested_action": {
                "summary": "Fix invalid JSON syntax in each failing JSON-LD block so machine readers can parse the facts.",
                "priority": "high",
                "impact": "high",
                "effort": "easy",
                "target_persona": "developer",
            },
        })

    price, cta, inventory, product_context = _commerce_signals(html)
    has_product = _has_product_entity(objects)
    transactional_page = _page_is_transactional(artifact, html, price, cta, inventory, product_context)
    if transactional_page and not has_product:
        findings.append({
            "rule_id": "SD-COMMERCE-001",
            "title": "Missing Product/Offer Schema on Transactional Page",
            "severity": "high",
            "evidence": "The page contains a price plus an explicit purchase CTA and additional product/inventory context, but no Product or Offer JSON-LD entity.",
            "suggested_action": {
                "summary": "Add Product and Offer JSON-LD with stable identifiers, price, currency, availability, and canonical product URL.",
                "priority": "high",
                "impact": "high",
                "effort": "medium",
                "target_persona": "developer",
                "recommended_snippet": {
                    "language": "json",
                    "code": json.dumps({
                        "@context": "https://schema.org",
                        "@type": "Product",
                        "name": "<PRODUCT_NAME>",
                        "offers": {
                            "@type": "Offer",
                            "price": "<PRICE>",
                            "priceCurrency": "<CURRENCY>",
                            "availability": "<AVAILABILITY_URL>",
                            "url": "<CANONICAL_URL>",
                        },
                    }, indent=2),
                },
            },
        })

    # --- Freshness & Stale-Fact Reasoning ---
    is_article = bool(types & {"Article", "NewsArticle", "BlogPosting"})
    last_mod_header = headers.get("Last-Modified") or headers.get("last-modified")
    parsed_header_date = parse_date(last_mod_header)

    pub_dates = []
    mod_dates = []
    malformed_dates = []

    for o in objects:
        if isinstance(o, dict):
            if o.get("datePublished"):
                raw_pub = str(o.get("datePublished"))
                dt = parse_date(raw_pub)
                if dt:
                    pub_dates.append((raw_pub, dt))
                else:
                    malformed_dates.append(("datePublished", raw_pub))
            if o.get("dateModified"):
                raw_mod = str(o.get("dateModified"))
                dt = parse_date(raw_mod)
                if dt:
                    mod_dates.append((raw_mod, dt))
                else:
                    malformed_dates.append(("dateModified", raw_mod))

    # Meta tags / OpenGraph dates
    og_pub = re.search(r'<meta\b[^>]*property=["\']article:published_time["\'][^>]*content=["\']([^"\']+)["\']', html, re.I)
    if og_pub:
        dt = parse_date(og_pub.group(1))
        if dt:
            pub_dates.append((og_pub.group(1), dt))
        else:
            malformed_dates.append(("article:published_time", og_pub.group(1)))
    og_mod = re.search(r'<meta\b[^>]*property=["\']article:modified_time["\'][^>]*content=["\']([^"\']+)["\']', html, re.I)
    if og_mod:
        dt = parse_date(og_mod.group(1))
        if dt:
            mod_dates.append((og_mod.group(1), dt))
        else:
            malformed_dates.append(("article:modified_time", og_mod.group(1)))

    for field_name, bad_val in malformed_dates:
        findings.append({
            "rule_id": "SD-FRESH-MALFORMED-001",
            "title": "Unparseable Content Timestamp in Structured Data",
            "severity": "medium",
            "evidence": f"Field '{field_name}' with value '{bad_val}' could not be parsed as a valid ISO-8601 date (CONTRADICTORY freshness state).",
            "suggested_action": {
                "summary": "Provide timestamps in standard ISO-8601 format (YYYY-MM-DD or YYYY-MM-DDThh:mm:ssZ).",
                "priority": "medium",
                "impact": "medium",
                "effort": "easy",
                "target_persona": "developer",
            },
        })

    has_date_signal = bool(pub_dates or mod_dates or parsed_header_date)

    if is_article and not has_date_signal and not malformed_dates:
        findings.append({
            "rule_id": "SD-FRESH-MISSING-001",
            "title": "Missing Freshness Signal",
            "severity": "medium",
            "evidence": "An article-like schema entity is present, but neither a schema publication/modification timestamp nor an HTTP Last-Modified header was found (MISSING freshness state).",
            "suggested_action": {
                "summary": "Expose datePublished/dateModified in structured data and maintain an accurate Last-Modified header.",
                "priority": "medium",
                "impact": "medium",
                "effort": "easy",
                "target_persona": "developer",
            },
        })

    audit_dt = parse_date(artifact.get("audited_at")) if artifact.get("audited_at") else DEFAULT_AUDIT_DATE
    if audit_dt is None:
        audit_dt = DEFAULT_AUDIT_DATE
    threshold_days = artifact.get("freshness_threshold_days", DEFAULT_STALE_THRESHOLD_DAYS)

    # 1. Stale-fact check: is the latest modification or publication older than threshold?
    latest_dt = None
    latest_str = ""
    for s, dt in mod_dates:
        if latest_dt is None or dt > latest_dt:
            latest_dt = dt
            latest_str = s
    if latest_dt is None and parsed_header_date:
        latest_dt = parsed_header_date
        latest_str = str(last_mod_header)
    if latest_dt is None:
        for s, dt in pub_dates:
            if latest_dt is None or dt > latest_dt:
                latest_dt = dt
                latest_str = s

    if latest_dt:
        age_days = (audit_dt - latest_dt).days
        if age_days > threshold_days:
            findings.append({
                "rule_id": "SD-FRESH-STALE-001",
                "title": "Potentially Stale Content / Outdated Freshness Signal",
                "severity": "medium",
                "evidence": f"Content timestamp ({latest_str}) indicates age of approximately {age_days} days relative to audit date ({audit_dt.strftime('%Y-%m-%d')}); freshness signal is outdated beyond configured threshold ({threshold_days} days).",
                "suggested_action": {
                    "summary": "Review content accuracy and update dateModified and Last-Modified headers to reflect recent verification.",
                    "priority": "medium",
                    "impact": "medium",
                    "effort": "easy",
                    "target_persona": "content_writer",
                },
            })
        elif age_days < -1:
            findings.append({
                "rule_id": "SD-FRESH-FUTURE-001",
                "title": "Anomalous Future Publication Date",
                "severity": "medium",
                "evidence": f"Date timestamp '{latest_str}' is set in the future ({abs(age_days)} days ahead) relative to audit reference date ({audit_dt.strftime('%Y-%m-%d')}).",
                "suggested_action": {
                    "summary": "Ensure timestamps reflect actual publication and modification times rather than placeholder or future dates.",
                    "priority": "medium",
                    "impact": "low",
                    "effort": "easy",
                    "target_persona": "developer",
                },
            })

    # 2. Inconsistent date progression: dateModified < datePublished
    if pub_dates and mod_dates:
        pub_str, p_dt = pub_dates[0]
        mod_str, m_dt = mod_dates[0]
        if m_dt < p_dt:
            findings.append({
                "rule_id": "SD-FRESH-CONTRADICT-001",
                "title": "Contradictory Publication and Modification Dates",
                "severity": "medium",
                "evidence": f"Structured data dateModified ('{mod_str}') is earlier than datePublished ('{pub_str}').",
                "suggested_action": {
                    "summary": "Align datePublished and dateModified so revisions reflect chronological progression.",
                    "priority": "medium",
                    "impact": "low",
                    "effort": "easy",
                    "target_persona": "developer",
                },
            })

    # 3. Conflicting timestamps: schema dateModified vs HTTP Last-Modified (> 365 days gap)
    if mod_dates and parsed_header_date:
        mod_str, m_dt = mod_dates[0]
        diff_days = abs((m_dt - parsed_header_date).days)
        if diff_days > 365:
            findings.append({
                "rule_id": "SD-FRESH-HEADER-CONFLICT-001",
                "title": "Conflicting Content Freshness Signals",
                "severity": "medium",
                "evidence": f"dateModified in structured data ('{mod_str}') differs by {diff_days} days from HTTP Last-Modified header ('{last_mod_header}').",
                "suggested_action": {
                    "summary": "Synchronize server Last-Modified headers with in-page structured data timestamps.",
                    "priority": "medium",
                    "impact": "medium",
                    "effort": "easy",
                    "target_persona": "developer",
                },
            })

    # --- Non-Text Fact Detection ---
    findings.extend(_check_non_text_facts(html))

    # --- Organization Entity Consistency & Disambiguation ---
    organizations = [o for o in objects if "Organization" in (o.get("@type") if isinstance(o.get("@type"), list) else [o.get("@type")])]
    if len(organizations) > 1 and not all(o.get("@id") for o in organizations):
        findings.append({
            "rule_id": "SD-ORG-DUPLICATE-001",
            "title": "Ambiguous Duplicate Organization Entities",
            "severity": "medium",
            "evidence": f"Found {len(organizations)} Organization entities without a stable @id on every definition, making entity resolution less deterministic.",
            "suggested_action": {
                "summary": "Use one canonical Organization entity with a stable @id and reference that entity consistently from related schema blocks.",
                "priority": "medium",
                "impact": "medium",
                "effort": "easy",
                "target_persona": "developer",
            },
        })

    canonical = _canonical(html) or url
    canonical_host = urlparse(canonical).netloc.lower()
    for org in organizations:
        org_url = org.get("url")
        if isinstance(org_url, str) and org_url:
            if canonical_host and urlparse(org_url).netloc.lower() and urlparse(org_url).netloc.lower() != canonical_host:
                findings.append({
                    "rule_id": "SD-ORG-HOST-001",
                    "title": "Organization URL Conflicts With Canonical Page",
                    "severity": "medium",
                    "evidence": f"Organization.url points to {org_url}, while the page canonical host is {canonical_host}.",
                    "suggested_action": {
                        "summary": "Align Organization.url with the canonical brand domain or explicitly use a stable @id to identify the intended entity.",
                        "priority": "medium",
                        "impact": "medium",
                        "effort": "easy",
                        "target_persona": "developer",
                    },
                })
        if not org.get("@id") and not org.get("sameAs"):
            findings.append({
                "rule_id": "SD-ORG-ID-001",
                "title": "Weak Organization Disambiguation",
                "severity": "medium",
                "evidence": "The Organization entity has neither @id nor sameAs, leaving fewer deterministic on-site identity signals.",
                "suggested_action": {
                    "summary": "Give the Organization a stable @id and add authoritative sameAs links for official identities where appropriate.",
                    "priority": "medium",
                    "impact": "medium",
                    "effort": "easy",
                    "target_persona": "developer",
                },
            })
    return {"findings": findings}


def audit_cross_page(page_artifacts):
    """
    Evaluates consistency of entity facts and detects conflicting statements
    across representative crawled pages (on-site corroboration).
    """
    findings = []
    if len(page_artifacts) < 2:
        return findings

    org_names = {}
    org_urls = {}
    product_prices = {}
    same_as_profiles = {}

    for page in page_artifacts:
        url = page.get("url", "")
        html = page.get("html", "")
        objects, _, _ = extract_json_ld_objects(html)

        for obj in objects:
            t = obj.get("@type")
            types_list = t if isinstance(t, list) else [t]
            if "Organization" in types_list:
                name = obj.get("name")
                if isinstance(name, str) and name.strip():
                    org_names.setdefault(name.strip(), []).append(url)
                o_url = obj.get("url")
                if isinstance(o_url, str) and o_url.strip():
                    org_urls.setdefault(o_url.strip(), []).append(url)
                same_as = obj.get("sameAs")
                if same_as:
                    sa_list = same_as if isinstance(same_as, list) else [same_as]
                    norm_sa = tuple(sorted(str(s).strip() for s in sa_list if s))
                    if norm_sa:
                        same_as_profiles.setdefault(norm_sa, []).append(url)

            if "Product" in types_list:
                prod_name = obj.get("name")
                offers = obj.get("offers")
                offer_list = offers if isinstance(offers, list) else [offers] if isinstance(offers, dict) else []
                for off in offer_list:
                    price = off.get("price")
                    if prod_name and price is not None:
                        key = str(prod_name).strip().lower()
                        product_prices.setdefault(key, []).append((url, str(price).strip(), str(prod_name).strip()))

    # 1. Conflicting Organization Names
    if len(org_names) > 1:
        details = "; ".join(f"'{n}' on {', '.join(urls[:2])}" for n, urls in org_names.items())
        findings.append({
            "rule_id": "ENT-CONFLICT-NAME-001",
            "title": "Conflicting Organization Names Across Sampled Pages",
            "severity": "high",
            "evidence": f"Sampled pages declare divergent Organization names: {details} (on-site corroboration).",
            "suggested_action": {
                "summary": "Establish one canonical Organization name and reference it consistently across all pages.",
                "priority": "high",
                "impact": "high",
                "effort": "easy",
                "target_persona": "content_writer",
            },
        })

    # 2. Conflicting Organization URLs
    if len(org_urls) > 1:
        details = "; ".join(f"'{u}' on {', '.join(urls[:2])}" for u, urls in org_urls.items())
        findings.append({
            "rule_id": "ENT-CONFLICT-URL-001",
            "title": "Conflicting Organization URLs Across Sampled Pages",
            "severity": "high",
            "evidence": f"Sampled pages declare divergent Organization URLs: {details} (on-site corroboration).",
            "suggested_action": {
                "summary": "Align Organization.url across all structured data entities to point to the canonical brand domain.",
                "priority": "high",
                "impact": "high",
                "effort": "easy",
                "target_persona": "developer",
            },
        })

    # 3. Conflicting Product Prices
    for prod_key, price_entries in product_prices.items():
        distinct_prices = {}
        for u, pr, real_name in price_entries:
            distinct_prices.setdefault(pr, []).append(u)
        if len(distinct_prices) > 1:
            price_details = "; ".join(f"price='{p}' on {', '.join(us[:2])}" for p, us in distinct_prices.items())
            first_name = price_entries[0][2]
            findings.append({
                "rule_id": "ENT-CONFLICT-PRICE-001",
                "title": "Conflicting Product Pricing Across Sampled Pages",
                "severity": "high",
                "evidence": f"Different sampled pages state conflicting prices for '{first_name}': {price_details} (on-site corroboration).",
                "suggested_action": {
                    "summary": "Establish one canonical source of truth and align conflicting page-level facts.",
                    "priority": "high",
                    "impact": "high",
                    "effort": "medium",
                    "target_persona": "marketing",
                },
            })

    return findings


def run_structured_data_audit(url, html_content, last_modified_header=None):
    return audit({"url": url, "html": html_content, "headers": {"Last-Modified": last_modified_header} if last_modified_header else {}})

