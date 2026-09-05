from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse
import re

# Word-boundary anchored vocabulary supporting English, Spanish, French, German, Italian, Portuguese
# ensuring ordinary words ("Cartoons", "Bookshelf", "Startup", "Shopify") are not falsely triggered.
CTA_RE = re.compile(
    r"\b(?:"
    # English
    r"buy|cart|contact|learn|start|sign|shop|book|demo|quote|order|subscribe|get|try|pricing|apply|join|claim|register|schedule|explore|download|enroll|request|inquire|inquiry|consult|consultation|submit|send|view|access|login|enter|"
    # Spanish
    r"comprar|carrito|contacto|contactar|aprender|iniciar|pedir|empezar|solicitar|reservar|unirse|aplicar|inscribirse|descargar|consultar|"
    # French
    r"acheter|panier|contacter|apprendre|commencer|commander|reserver|demander|rejoindre|postuler|inscrire|telecharger|consulter|"
    # German
    r"kaufen|warenkorb|kontaktieren|lernen|starten|bestellen|buchen|anfordern|beitreten|bewerben|anmelden|herunterladen|anfragen|"
    # Italian & Portuguese
    r"comprare|acquista|carrello|contatto|contattaci|inizia|ordina|prenota|carrinho|comecar|inscrever|aderir|richiedi"
    r")\b",
    re.IGNORECASE,
)


class EngagementParser(HTMLParser):
    def __init__(self, page_url=""):
        super().__init__()
        self.page_url = page_url
        self.host = urlparse(page_url).netloc.lower() if page_url else ""
        self.h1_texts = []
        self.title_text = []
        self._in_h1 = False
        self._in_title = False
        self._in_p = False
        self._paragraph = []
        self.long_paragraphs = 0
        self.internal_links = 0
        self.ctas = 0
        self.in_body = False
        self._in_cta_tag = False
        self._cta_attrs_blob = ""
        self._cta_text = []

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        attrs = dict(attrs)
        if tag == "body": self.in_body = True
        if tag == "h1": self._in_h1 = True; self._current_h1 = []
        if tag == "title": self._in_title = True
        if tag == "p": self._in_p = True; self._paragraph = []
        if tag == "a":
            href = (attrs.get("href", "") or "").strip()
            if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                resolved = urljoin(self.page_url, href) if self.page_url else href
                parsed = urlparse(resolved)
                if parsed.scheme in ("http", "https"):
                    if not self.host or parsed.netloc.lower() == self.host:
                        self.internal_links += 1
                elif href.startswith("/") and not href.startswith("//"):
                    self.internal_links += 1
                elif not (href.startswith("//") or "://" in href):
                    self.internal_links += 1
        if tag == "input":
            # Void element: check type=submit/button or value for CTA vocabulary
            inp_type = (attrs.get("type", "") or "").lower()
            if inp_type in ("submit", "button"):
                self.ctas += 1
            else:
                blob = " ".join(str(v or "") for v in attrs.values()).lower()
                if CTA_RE.search(blob):
                    self.ctas += 1
        elif tag in {"button", "a"}:
            self._in_cta_tag = True
            role = (attrs.get("role", "") or "").lower().strip()
            cls = (attrs.get("class", "") or "").lower()
            cls_parts = cls.split()
            
            self._structural_cta = (
                tag == "button" 
                or role == "button"
                or "btn" in cls_parts or "cta" in cls_parts or "button" in cls_parts
                or "cta-" in cls or "-cta" in cls
            )
            self._cta_attrs_blob = " ".join(str(v or "") for v in attrs.values()).lower()
            self._cta_text = []

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag == "h1" and self._in_h1:
            self.h1_texts.append(" ".join(self._current_h1).strip())
            self._in_h1 = False
        if tag == "title": self._in_title = False
        if tag == "p" and self._in_p:
            if len(" ".join(self._paragraph).strip()) > 800: self.long_paragraphs += 1
            self._in_p = False
            self._paragraph = []
        if tag in {"button", "a"} and self._in_cta_tag:
            combined = (self._cta_attrs_blob + " " + " ".join(self._cta_text)).lower()
            if self._structural_cta or CTA_RE.search(combined):
                self.ctas += 1
            self._in_cta_tag = False
            self._structural_cta = False
            self._cta_attrs_blob = ""
            self._cta_text = []

    def handle_data(self, data):
        text = data.strip()
        if not text: return
        if self._in_h1: self._current_h1.append(text)
        if self._in_title: self.title_text.append(text)
        if self._in_p: self._paragraph.append(text)
        if self._in_cta_tag: self._cta_text.append(text)


def parse_canonicals(html, base_url=""):
    """
    Extracts all canonical link tags, handling attribute order, relative URLs,
    and fragment removal.
    """
    canonicals = []
    p1 = re.compile(r'<link\b[^>]*?\brel=["\']canonical["\'][^>]*?\bhref=["\']([^"\']*)["\']', re.I)
    p2 = re.compile(r'<link\b[^>]*?\bhref=["\']([^"\']*)["\'][^>]*?\brel=["\']canonical["\']', re.I)

    for m in p1.finditer(html or ""):
        canonicals.append(m.group(1).strip())
    for m in p2.finditer(html or ""):
        href = m.group(1).strip()
        if href not in canonicals:
            canonicals.append(href)

    return canonicals


def classify_page_intent(url, html, h1_texts=None, ctas=0):
    """
    Multi-signal page-intent classification:
    Evaluates path, Schema @type, title/headings, and page copy signals.
    """
    parsed = urlparse(url or "")
    path = parsed.path.lower()
    html_lower = (html or "").lower()
    h1_combined = " ".join(h1_texts or []).lower()

    signals = {
        "homepage": 0, "product": 0, "service": 0, "article": 0,
        "about": 0, "contact": 0, "faq": 0, "category": 0
    }

    # Homepage signals
    if path in ("", "/", "/index.html", "/home"):
        signals["homepage"] += 3

    # Product signals
    if re.search(r'/(?:products?|items?|p|dp)/', path): signals["product"] += 2
    if '"@type": "product"' in html_lower or '"@type":"product"' in html_lower: signals["product"] += 3
    if re.search(r'\b(?:add to cart|buy now|in stock|price|sku)\b', html_lower): signals["product"] += 1

    # Service signals
    if re.search(r'/(?:services?|solutions?|practices?)/', path): signals["service"] += 2
    if '"@type": "service"' in html_lower or '"@type":"service"' in html_lower: signals["service"] += 3
    if re.search(r'\b(?:our services|what we do|consulting|capabilities)\b', h1_combined): signals["service"] += 2

    # Article / Blog signals
    if re.search(r'/(?:blog|news|articles?|posts?|insights?)/', path): signals["article"] += 2
    if any(t in html_lower for t in ('"article"', '"newsarticle"', '"blogposting"')): signals["article"] += 3

    # About signals
    if re.search(r'/(?:about|about-us|company|team|leadership|who-we-are)', path): signals["about"] += 2
    if re.search(r'\b(?:about us|our team|our mission|who we are)\b', h1_combined): signals["about"] += 2

    # Contact signals
    if re.search(r'/(?:contact|contact-us|support|help-center|get-in-touch)', path): signals["contact"] += 2
    if re.search(r'\b(?:contact us|get in touch|send a message)\b', h1_combined): signals["contact"] += 2

    # FAQ signals
    if re.search(r'/(?:faq|faqs|frequently-asked-questions)', path): signals["faq"] += 2
    if '"@type": "faqpage"' in html_lower or '"@type":"faqpage"' in html_lower: signals["faq"] += 3
    if "frequently asked questions" in h1_combined or "faq" in h1_combined: signals["faq"] += 2

    # Category signals
    if re.search(r'/(?:categories?|collections?|catalog|shop|store)/', path): signals["category"] += 2

    best_intent = max(signals.items(), key=lambda kv: kv[1])
    return best_intent[0] if best_intent[1] >= 2 else "general"


def audit(artifact):
    status = artifact.get("status_code", 200)
    fetch_mode = artifact.get("fetch_mode", "http_static")
    html = artifact.get("html", "") or ""
    url = artifact.get("url", "")
    extraction_uncertain = artifact.get("extraction_uncertain", False)
    is_spa_shell = artifact.get("is_spa_shell", False)
    allow_absence = not (extraction_uncertain or is_spa_shell)

    # False-absence guard: never report missing content or structure if fetch failed or content is non-HTML
    if (status is not None and status != 200 and status != 0) or fetch_mode == "unsupported_content_type" or not html:
        return {"findings": []}

    parser = EngagementParser(page_url=url)
    parser.feed(html)
    findings = []
    h1_count = len(parser.h1_texts)
    title_str = " ".join(parser.title_text).strip()

    if h1_count == 0:
        if allow_absence:
            findings.append({
                "rule_id": "ENG-H1-ZERO-001",
                "title": "Missing H1 Heading",
                "severity": "medium",
                "evidence": "The document contains 0 structural <h1> elements.",
                "suggested_action": {
                    "summary": "Add one concise H1 that states the page's primary topic or value proposition.",
                    "priority": "medium",
                    "impact": "high",
                    "effort": "easy",
                    "target_persona": "content_writer",
                },
            })
    elif h1_count > 1:
        evidence = ", ".join(repr(x) for x in parser.h1_texts[:3])
        findings.append({
            "rule_id": "ENG-H1-MULTI-001",
            "title": "Multiple H1 Headings",
            "severity": "medium",
            "evidence": f"The document contains {h1_count} structural <h1> elements: {evidence}.",
            "suggested_action": {
                "summary": "Use one primary H1 and demote secondary topics to H2/H3 headings so the page has a clear primary subject.",
                "priority": "medium",
                "impact": "medium",
                "effort": "easy",
                "target_persona": "content_writer",
            },
        })

    if not parser.title_text and h1_count == 0:
        if allow_absence:
            findings.append({
                "rule_id": "ENG-ORIENTATION-MISSING-001",
                "title": "Missing Page Orientation",
                "severity": "high",
                "evidence": "Neither a non-empty <title> nor a structural <h1> was found in the document.",
                "suggested_action": {
                    "summary": "Add a descriptive page title and primary H1 that identify the page's purpose and entity.",
                    "priority": "high",
                    "impact": "high",
                    "effort": "easy",
                    "target_persona": "content_writer",
                    "recommended_snippet": {
                        "language": "html",
                        "code": "<title>YOUR_PAGE_TOPIC - YOUR_BRAND_NAME</title>\n<h1>YOUR_PAGE_TOPIC</h1>",
                    },
                },
            })
    elif title_str.lower() in {"home", "untitled", "page 1", "welcome", "default"}:
        findings.append({
            "rule_id": "ENG-TITLE-GENERIC-001",
            "title": "Generic or Uninformative Page Title",
            "severity": "medium",
            "evidence": f"Page title '{title_str}' is generic and does not convey the specific entity or topic.",
            "suggested_action": {
                "summary": "Expand title tag to include the distinctive topic and brand name for AI extractors and searchers.",
                "priority": "medium",
                "impact": "medium",
                "effort": "easy",
                "target_persona": "content_writer",
                "recommended_snippet": {
                    "language": "html",
                    "code": f"<title>Descriptive Topic - YOUR_BRAND_NAME</title>",
                },
            },
        })

    # --- Robust Canonical Checks ---
    raw_canonicals = parse_canonicals(html, url)
    if len(raw_canonicals) > 1:
        # Check if they point to different targets
        normalized_targets = set()
        for c in raw_canonicals:
            abs_c = urljoin(url, c) if url else c
            # strip fragment
            clean_c = abs_c.split("#")[0]
            normalized_targets.add(clean_c)

        if len(normalized_targets) > 1:
            findings.append({
                "rule_id": "ENG-CANONICAL-DIVERGENT-001",
                "title": "Conflicting Canonical Link Tags",
                "severity": "high",
                "evidence": f"Found {len(raw_canonicals)} canonical tags pointing to divergent URLs: {', '.join(raw_canonicals)}.",
                "suggested_action": {
                    "summary": "Remove conflicting canonical link elements and maintain exactly one authoritative canonical URL per page.",
                    "priority": "high",
                    "impact": "high",
                    "effort": "easy",
                    "target_persona": "developer",
                },
            })
        else:
            findings.append({
                "rule_id": "ENG-CANONICAL-DUP-001",
                "title": "Duplicate Canonical Link Tags",
                "severity": "medium",
                "evidence": f"Document contains {len(raw_canonicals)} duplicate canonical tags pointing to the same URL.",
                "suggested_action": {
                    "summary": "Remove redundant canonical tags so HTML head contains exactly one link rel=canonical declaration.",
                    "priority": "medium",
                    "impact": "low",
                    "effort": "easy",
                    "target_persona": "developer",
                },
            })
    elif len(raw_canonicals) == 1:
        raw_c = raw_canonicals[0]
        if "#" in raw_c:
            findings.append({
                "rule_id": "ENG-CANONICAL-FRAG-001",
                "title": "Canonical Tag Contains URL Fragment",
                "severity": "medium",
                "evidence": f"Canonical URL '{raw_c}' contains a fragment identifier ('#{raw_c.split('#', 1)[1]}'); canonical tags must specify document URLs without fragments.",
                "suggested_action": {
                    "summary": "Strip URL fragments from canonical tags so bots index the clean document path.",
                    "priority": "medium",
                    "impact": "medium",
                    "effort": "easy",
                    "target_persona": "developer",
                },
            })
        abs_c = urljoin(url, raw_c) if url else raw_c
        c_host = urlparse(abs_c).netloc.lower()
        if parser.host and c_host and c_host != parser.host:
            findings.append({
                "rule_id": "ENG-CANONICAL-HOST-001",
                "title": "Cross-Origin Canonical Directive",
                "severity": "medium",
                "evidence": f"Canonical URL points to external domain '{c_host}' while page resides on '{parser.host}'.",
                "suggested_action": {
                    "summary": "Verify cross-origin canonicalization is intentional (e.g. syndicated content) rather than a staging/domain configuration error.",
                    "priority": "medium",
                    "impact": "medium",
                    "effort": "easy",
                    "target_persona": "seo_team",
                },
            })

    if parser.long_paragraphs:
        findings.append({
            "rule_id": "ENG-SCANNABLE-001",
            "title": "Poor Text Scannability",
            "severity": "medium",
            "evidence": f"Found {parser.long_paragraphs} paragraph(s) exceeding 800 characters without a structural break.",
            "suggested_action": {
                "summary": "Break dense copy into shorter paragraphs, bullets, and descriptive H2/H3 sections so visitors and summarizers can retain context.",
                "priority": "medium",
                "impact": "medium",
                "effort": "easy",
                "target_persona": "content_writer",
            },
        })

    if parser.in_body and parser.internal_links == 0:
        if allow_absence:
            findings.append({
                "rule_id": "ENG-NAV-DEADEND-001",
                "title": "Navigational Dead End",
                "severity": "high",
                "evidence": "No internal navigation links were found in the body of the page.",
                "suggested_action": {
                    "summary": "Add contextual internal links to the next relevant product, service, proof, or contact step.",
                    "priority": "high",
                    "impact": "high",
                    "effort": "medium",
                    "target_persona": "content_writer",
                },
            })

    if parser.in_body and parser.ctas == 0:
        if allow_absence:
            findings.append({
                "rule_id": "ENG-CTA-MISSING-001",
                "title": "No Obvious Next Action",
                "severity": "medium",
                "evidence": "No obvious CTA-like button, link, or input label was detected using the audit's conservative action vocabulary.",
                "suggested_action": {
                    "summary": "Add a clear next action appropriate to the page intent, such as Contact, Learn More, Buy, Book, or Request a Demo.",
                    "priority": "medium",
                    "impact": "medium",
                    "effort": "easy",
                    "target_persona": "marketing",
                },
            })
    return {"findings": findings}


def run_engagement_audit(url, html_content):
    return audit({"url": url, "html": html_content})

