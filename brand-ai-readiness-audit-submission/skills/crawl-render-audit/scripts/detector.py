import re
from html.parser import HTMLParser


class TextExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.parts = []
        self._ignored = 0

    def handle_starttag(self, tag, attrs):
        if tag.lower() in {"script", "style", "noscript", "template"}:
            self._ignored += 1

    def handle_endtag(self, tag):
        if tag.lower() in {"script", "style", "noscript", "template"} and self._ignored:
            self._ignored -= 1

    def handle_data(self, data):
        if not self._ignored and data.strip():
            self.parts.append(data.strip())

    def text(self):
        return " ".join(self.parts)


def readable_text(html):
    parser = TextExtractor()
    parser.feed(html or "")
    return parser.text()


def parse_robots_directives(html, headers=None):
    """
    Extracts robots directives from both HTTP headers (X-Robots-Tag)
    and HTML meta tags (robots, googlebot, etc.).
    """
    directives = []
    headers = headers or {}

    # HTTP Header: X-Robots-Tag (case-insensitive)
    for k, v in headers.items():
        if k.lower() == "x-robots-tag" and v:
            directives.append({
                "source": "header",
                "name": "X-Robots-Tag",
                "content": str(v).strip(),
                "raw": f"X-Robots-Tag: {v}",
            })

    # Meta tags in HTML (both name...content and content...name attribute orders)
    p1 = re.compile(r'<meta\b[^>]*?\bname=["\']([a-zA-Z0-9_-]+)["\'][^>]*?\bcontent=["\']([^"\']*)["\']', re.I)
    p2 = re.compile(r'<meta\b[^>]*?\bcontent=["\']([^"\']*)["\'][^>]*?\bname=["\']([a-zA-Z0-9_-]+)["\']', re.I)

    target_bots = {"robots", "googlebot", "bingbot", "slurp", "duckduckbot", "baiduspider", "yandex"}

    for m in p1.finditer(html or ""):
        b_name, b_content = m.group(1).lower(), m.group(2)
        if b_name in target_bots:
            directives.append({
                "source": "meta",
                "name": b_name,
                "content": b_content.strip(),
                "raw": m.group(0),
            })

    for m in p2.finditer(html or ""):
        b_content, b_name = m.group(1), m.group(2).lower()
        if b_name in target_bots:
            directives.append({
                "source": "meta",
                "name": b_name,
                "content": b_content.strip(),
                "raw": m.group(0),
            })

    return directives


def audit(artifact):
    findings = []
    status = artifact.get("status_code", 0)
    html = artifact.get("html", "") or ""
    headers = artifact.get("headers", {}) or {}
    rendered = artifact.get("rendered_html")
    robots_allowed = artifact.get("robots_allowed", None)

    if status >= 400 or status == 0:
        severity = "critical" if status >= 500 else "high"
        findings.append({
            "rule_id": "CR-STATUS-001",
            "title": f"Target Page Returned {status or 'No HTTP Response'}",
            "severity": severity,
            "evidence": f"The target page did not return a successful HTML response (status={status}).",
            "suggested_action": {
                "summary": "Make the public page reliably return a successful HTML response to crawlers.",
                "priority": severity,
                "impact": "high",
                "effort": "easy",
                "target_persona": "developer",
            },
        })
        return {"findings": findings}

    # --- Indexability / Robots Directives Audit ---
    directives = parse_robots_directives(html, headers)
    has_noindex = False
    has_index = False
    has_nofollow = False
    noindex_evidence = []
    nofollow_evidence = []

    for d in directives:
        tokens = [t.strip().lower() for t in d["content"].split(",") if t.strip()]
        if "noindex" in tokens or "none" in tokens:
            has_noindex = True
            noindex_evidence.append(f"{d['source'].upper()} {d['name']}: '{d['content']}'")
        if "index" in tokens or "all" in tokens:
            has_index = True
        if "nofollow" in tokens or "none" in tokens:
            has_nofollow = True
            nofollow_evidence.append(f"{d['source'].upper()} {d['name']}: '{d['content']}'")

    if has_noindex:
        ev_str = "; ".join(noindex_evidence)
        if robots_allowed is True:
            ev_str += " (Note: robots.txt allows crawling, but page-level directive prevents indexing)."
        findings.append({
            "rule_id": "CR-NOINDEX-001",
            "title": "Noindex Directive Blocks Machine Indexing",
            "severity": "critical",
            "evidence": f"Page specifies an indexing disallow directive: {ev_str}.",
            "suggested_action": {
                "summary": "Remove noindex or none directives from public pages intended to be discoverable and cited by AI engines.",
                "priority": "critical",
                "impact": "high",
                "effort": "easy",
                "target_persona": "developer",
                "recommended_snippet": {
                    "language": "html",
                    "code": '<meta name="robots" content="index, follow">',
                },
            },
        })
    elif has_nofollow:
        ev_str = "; ".join(nofollow_evidence)
        findings.append({
            "rule_id": "CR-NOFOLLOW-001",
            "title": "Nofollow Directive Restricts Link Traversal",
            "severity": "medium",
            "evidence": f"Page specifies a link-traversal restriction: {ev_str}.",
            "suggested_action": {
                "summary": "Review whether crawler link following should be permitted so connected pages can be discovered.",
                "priority": "medium",
                "impact": "medium",
                "effort": "easy",
                "target_persona": "seo_team",
            },
        })

    if has_noindex and has_index:
        findings.append({
            "rule_id": "CR-DIRECTIVE-CONFLICT-001",
            "title": "Conflicting Indexing Directives",
            "severity": "medium",
            "evidence": f"Found contradictory 'index' and 'noindex' directives across headers or meta tags on the same page.",
            "suggested_action": {
                "summary": "Establish a single, unambiguous indexing policy for search crawlers and AI bots.",
                "priority": "medium",
                "impact": "medium",
                "effort": "easy",
                "target_persona": "developer",
            },
        })

    # --- Readability & Client-Side Rendering Audit ---
    text = readable_text(html)
    lower_html = html.lower()
    root_match = re.search(r'<(?:div|main|span)[^>]+id=["\'](?:root|app|__next|__nuxt)["\'][^>]*>\s*</(?:div|main|span)>', html, re.I)
    hydration = bool(re.search(r'__next_data__|__nuxt__|data-reactroot|ng-version|webpackJsonp|reactroot', html, re.I))
    scripts = len(re.findall(r'<script\b', lower_html))
    script_bytes = sum(len(m.group(0)) for m in re.finditer(r'<script\b[^>]*>.*?</script\s*>', html, re.I | re.S))
    raw_bytes = max(len(html.encode("utf-8")), 1)

    if root_match and len(text) < 500:
        findings.append({
            "rule_id": "CR-RENDER-SPA-001",
            "title": "Likely Client-Side Rendering Dependency",
            "severity": "high",
            "evidence": f"An empty SPA mount was found and readable raw text is only {len(text)} characters; this is static evidence that substantive content may be assembled after load.",
            "suggested_action": {
                "summary": "Expose core page facts in initial HTML through server-side rendering or equivalent pre-rendering.",
                "priority": "high",
                "impact": "high",
                "effort": "hard",
                "target_persona": "developer",
            },
        })
    elif hydration and len(text) < 300 and scripts >= 2:
        findings.append({
            "rule_id": "CR-RENDER-HYDRATION-001",
            "title": "Likely JavaScript-Dependent Initial Content",
            "severity": "high",
            "evidence": f"Hydration/framework markers were found with only {len(text)} readable raw-text characters and {scripts} script elements; this is a static inference, not a rendered-DOM measurement.",
            "suggested_action": {
                "summary": "Ensure important entity facts and page copy are present in the initial HTML rather than requiring client-side execution.",
                "priority": "high",
                "impact": "high",
                "effort": "hard",
                "target_persona": "developer",
            },
        })
    elif scripts >= 4 and script_bytes / raw_bytes > 0.70 and len(text) < 800:
        findings.append({
            "rule_id": "CR-RENDER-SCRIPTHEAVY-001",
            "title": "Script-Heavy Page With Limited Raw Text",
            "severity": "medium",
            "evidence": f"Scripts account for approximately {script_bytes / raw_bytes:.0%} of the HTML payload while readable raw text is {len(text)} characters; this is a static rendering-risk signal.",
            "suggested_action": {
                "summary": "Move essential facts and navigation into server-delivered HTML and reserve JavaScript for progressive enhancement.",
                "priority": "medium",
                "impact": "medium",
                "effort": "medium",
                "target_persona": "developer",
            },
        })

    if rendered:
        raw_source = artifact.get("static_html") if artifact.get("static_html") is not None else html
        raw_len = len(readable_text(raw_source))
        rendered_len = len(readable_text(rendered))
        if rendered_len - raw_len > 500:
            findings.append({
                "rule_id": "CR-RENDER-GAP-001",
                "title": "Rendered Content Exceeds Raw HTML Content",
                "severity": "high",
                "evidence": f"Provided rendered HTML contains {rendered_len} readable characters versus {raw_len} in the raw response, a gap of {rendered_len - raw_len} characters.",
                "suggested_action": {
                    "summary": "Server-render the core content that is required for machine discovery so it is available without browser execution.",
                    "priority": "high",
                    "impact": "high",
                    "effort": "hard",
                    "target_persona": "developer",
                },
            })

    return {"findings": findings}


def run_crawl_audit(url, status_code, robots_txt_content, raw_html, rendered_html=None):
    artifact = {"url": url, "status_code": status_code, "html": raw_html, "rendered_html": rendered_html}
    result = audit(artifact)
    if robots_txt_content:
        # Compatibility helper for direct detector tests; the orchestrator remains the policy authority.
        import urllib.robotparser
        parser = urllib.robotparser.RobotFileParser()
        parser.parse(robots_txt_content.splitlines())
        if not parser.can_fetch("BrandAIAuditBot/1.0", url):
            result["findings"].append({
                "rule_id": "CR-ROBOTS-001",
                "title": "Content Blocked by robots.txt",
                "severity": "critical",
                "evidence": "The supplied robots.txt directives disallow the target URL for BrandAIAuditBot/1.0.",
                "suggested_action": {
                    "summary": "Review robots.txt and allow paths intended to be discoverable by AI agents.",
                    "priority": "critical",
                    "impact": "high",
                    "effort": "easy",
                    "target_persona": "developer",
                },
            })
    return result["findings"]
