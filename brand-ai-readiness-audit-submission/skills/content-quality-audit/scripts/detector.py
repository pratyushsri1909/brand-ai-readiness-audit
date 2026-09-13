"""
content-quality-audit detector
================================
Deterministic, read-only content quality checks across one or more page artifacts.

Checks implemented:
  A. Main content extraction excluding boilerplate (header, nav, footer, cookie banners)
  B. Thin content (page-type-sensitive thresholds on substantive main content)
  C. Exact duplicate detection (SHA-256 of normalised substantive text)
  D. Near-duplicate detection (SequenceMatcher and character 3-gram Jaccard >= 0.85)
  E. Potential topic overlap (term Jaccard >= 0.70)
  F. Meta-description completeness

Zero external network requests. Zero third-party dependencies.
"""
import difflib
import hashlib
import re
from html.parser import HTMLParser


# ---------------------------------------------------------------------------
# Page-type-sensitive thin-content word thresholds
# ---------------------------------------------------------------------------
THIN_THRESHOLDS = {
    "article": 250,
    "blog": 250,
    "product": 80,
    "homepage": 30,
    "category": 50,
    "about": 100,
    "contact": 40,
    "faq": 100,
    "general": 100,
    "unknown": 100,
}

# Similarity thresholds
EXACT_DUP_LABEL = "exact"
NEAR_DUP_JACCARD = 0.85
TOPIC_OVERLAP_JACCARD = 0.70

# Maximum shingles to compute (keeps runtime bounded)
MAX_SHINGLES = 200
SHINGLE_SIZE = 3  # character n-gram size


# ---------------------------------------------------------------------------
# Deterministic Main Content Extractor
# ---------------------------------------------------------------------------
class MainContentExtractor(HTMLParser):
    """
    Extracts substantive main content by identifying <main>, <article>, or
    content containers while filtering boilerplate tags (<header>, <nav>,
    <footer>, <aside>, cookie banners/consent dialogs, scripts, styles).
    """

    BOILERPLATE_TAGS = {"script", "style", "noscript", "template", "svg", "head", "header", "nav", "footer", "aside", "dialog"}
    CONTAINER_TAGS = {"main", "article"}

    def __init__(self):
        super().__init__()
        self.main_parts = []
        self.article_parts = []
        self.body_parts = []
        self.boilerplate_parts = []

        self._tag_stack = []
        self._excluded_depth = 0
        self._main_depth = 0
        self._article_depth = 0

    def handle_starttag(self, tag, attrs):
        tag_lower = tag.lower()
        attr_dict = dict(attrs)
        class_id_str = f"{attr_dict.get('class', '')} {attr_dict.get('id', '')}".lower()

        # Detect cookie / consent banners or modals
        is_banner = bool(re.search(r"\b(?:cookie|consent|banner|gdpr|modal-overlay|dialog)\b", class_id_str))
        is_boilerplate_tag = tag_lower in self.BOILERPLATE_TAGS

        is_excluded = is_boilerplate_tag or is_banner
        if is_excluded:
            self._excluded_depth += 1

        self._tag_stack.append((tag_lower, is_excluded))

        # Only register main/article if NOT currently inside an excluded/boilerplate container
        if self._excluded_depth == 0:
            if tag_lower == "main":
                self._main_depth += 1
            elif tag_lower == "article":
                self._article_depth += 1

    def handle_endtag(self, tag):
        tag_lower = tag.lower()
        if self._tag_stack:
            # Pop matching start tag from stack
            for idx in range(len(self._tag_stack) - 1, -1, -1):
                st_tag, st_excluded = self._tag_stack[idx]
                if st_tag == tag_lower:
                    if st_excluded and self._excluded_depth > 0:
                        self._excluded_depth -= 1
                    self._tag_stack.pop(idx)
                    break

        if tag_lower == "main" and self._main_depth > 0:
            self._main_depth -= 1
        elif tag_lower == "article" and self._article_depth > 0:
            self._article_depth -= 1

    def handle_data(self, data):
        text = data.strip()
        if not text:
            return

        if self._excluded_depth > 0:
            self.boilerplate_parts.append(text)
            return

        if self._main_depth > 0:
            self.main_parts.append(text)
        elif self._article_depth > 0:
            self.article_parts.append(text)
        else:
            self.body_parts.append(text)


def extract_main_content_text(html):
    """
    Extracts substantive main content and metadata from HTML.
    Returns (main_text, metadata).
    """
    if not html:
        return "", {"content_source": "empty", "content_length": 0, "excluded_boilerplate_length": 0}

    parser = MainContentExtractor()
    parser.feed(html)

    boilerplate_len = sum(len(p) for p in parser.boilerplate_parts)

    if parser.main_parts:
        content = " ".join(parser.main_parts)
        source = "main"
    elif parser.article_parts:
        content = " ".join(parser.article_parts)
        source = "article"
    elif parser.body_parts:
        content = " ".join(parser.body_parts)
        source = "body_filtered"
    else:
        # Requirement 16: If substantive content cannot be extracted, do NOT fall back to boilerplate
        content = ""
        source = "empty"

    return content, {
        "content_source": source,
        "content_length": len(content),
        "excluded_boilerplate_length": boilerplate_len,
    }


def _visible_text(html):
    """Returns cleaned substantive visible text from an HTML string excluding boilerplate."""
    main_text, _ = extract_main_content_text(html)
    return main_text


# ---------------------------------------------------------------------------
# Normalisation helpers
# ---------------------------------------------------------------------------
def _normalise_body(text):
    """Lowercase, remove punctuation, collapse whitespace."""
    t = text.lower()
    t = re.sub(r"[^\w\s]", " ", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def _word_count(text):
    """Counts space-separated tokens."""
    if not text:
        return 0
    return len(text.split())


def _body_hash(normalised_text):
    """SHA-256 hex digest of normalised body."""
    return hashlib.sha256(normalised_text.encode("utf-8", errors="replace")).hexdigest()


# ---------------------------------------------------------------------------
# Shingling for near-duplicate / topic-overlap
# ---------------------------------------------------------------------------
def _shingles(text, n=SHINGLE_SIZE, cap=MAX_SHINGLES):
    """Returns a frozenset of up to `cap` character n-grams."""
    if len(text) < n:
        return frozenset()
    all_shingles = {text[i: i + n] for i in range(len(text) - n + 1)}
    if len(all_shingles) > cap:
        # Deterministic subset: sort and take first `cap`
        all_shingles = frozenset(sorted(all_shingles)[:cap])
    return frozenset(all_shingles)


def _jaccard(set_a, set_b):
    """Jaccard similarity between two frozensets. Returns 0.0 if both empty."""
    if not set_a and not set_b:
        return 0.0
    union = set_a | set_b
    if not union:
        return 0.0
    return len(set_a & set_b) / len(union)


# ---------------------------------------------------------------------------
# Term-overlap for potential topic overlap with stopword filtering
# ---------------------------------------------------------------------------
GENERIC_STOPWORDS = {
    # Generic web / boilerplate tokens (Requirement 17)
    "about", "contact", "privacy", "cookie", "cookies", "copyright", "rights", "terms",
    "policy", "reserved", "disclaimer", "accessibility", "sitemap", "subscribe", "newsletter",
    "navigation", "footer", "header", "menu", "search", "login", "signin", "signup",
    "register", "website", "online", "click", "email", "phone", "address",
    # Common English stopwords
    "their", "there", "these", "those", "which", "would", "could", "should", "other",
    "after", "first", "great", "where", "being", "under", "while", "never", "every",
    "through", "before", "between", "during", "without", "again", "further", "always",
    # Multilingual common stopwords
    "sobre", "contacto", "politica", "derechos", "reservados", "aviso",  # ES
    "propos", "mentions", "legales", "politique", "droits", "tous",      # FR
    "ueber", "impressum", "datenschutz", "kontakt", "rechte", "alle",   # DE
    "contatto", "diritti", "riservati", "informativa",                  # IT
}


def _top_terms(text, top_n=10, min_len=5):
    """Returns frozenset of top-N most frequent substantive words excluding stopwords."""
    words = re.findall(r"[a-z]{%d,}" % min_len, text.lower())
    freq = {}
    for w in words:
        if w in GENERIC_STOPWORDS:
            continue
        freq[w] = freq.get(w, 0) + 1
    sorted_words = sorted(freq, key=lambda w: freq[w], reverse=True)
    return frozenset(sorted_words[:top_n])


# ---------------------------------------------------------------------------
# Meta-description extractor
# ---------------------------------------------------------------------------
def _meta_description(html):
    """Returns the content of the first meta[name=description], or ''."""
    html = html or ""
    # Attribute order: name then content
    m = re.search(
        r'<meta\b[^>]*?\bname=["\']description["\'][^>]*?\bcontent=["\']([^"\']*)["\']',
        html, re.I
    )
    if not m:
        # Attribute order: content then name
        m = re.search(
            r'<meta\b[^>]*?\bcontent=["\']([^"\']*)["\'][^>]*?\bname=["\']description["\']',
            html, re.I
        )
    return m.group(1).strip() if m else None


# ---------------------------------------------------------------------------
# Page role mapping helper
# ---------------------------------------------------------------------------
def _canonical_role(role):
    """Maps inferred roles to threshold bucket keys."""
    if not role:
        return "general"
    r = str(role).lower()
    if r in THIN_THRESHOLDS:
        return r
    if "article" in r or "blog" in r or "news" in r or "post" in r:
        return "article"
    if "product" in r or "service" in r:
        return "product"
    if "home" in r:
        return "homepage"
    if "categor" in r or "catalog" in r or "shop" in r:
        return "category"
    if "about" in r or "team" in r or "company" in r:
        return "about"
    if "contact" in r or "support" in r:
        return "contact"
    if "faq" in r:
        return "faq"
    return "general"


# ---------------------------------------------------------------------------
# Single-page checks
# ---------------------------------------------------------------------------
def _check_thin_content(url, html, page_role):
    """Returns a finding dict or None."""
    text = _visible_text(html)
    wc = _word_count(text)
    role_key = _canonical_role(page_role)
    threshold = THIN_THRESHOLDS.get(role_key, 100)

    if wc < threshold:
        return {
            "rule_id": "CQ-THIN-001",
            "title": "Thin Content Detected",
            "severity": "medium",
            "evidence": (
                f"Page at '{url}' (inferred role: {role_key}) contains approximately "
                f"{wc} visible words of substantive main content, below the {threshold}-word threshold for this page type."
            ),
            "suggested_action": {
                "summary": (
                    f"Expand the body content on this {role_key} page with substantive, "
                    "factual information relevant to the user intent to improve machine-readable "
                    "content depth for AI answer engines."
                ),
                "priority": "medium",
                "impact": "medium",
                "effort": "medium",
                "target_persona": "content_writer",
            },
            "content_quality_detail": {
                "word_count": wc,
                "threshold": threshold,
                "page_role": role_key,
            },
        }
    return None


def _check_meta_description(url, html):
    """Returns a finding dict or None."""
    meta_desc = _meta_description(html)
    if meta_desc is None:
        return {
            "rule_id": "CQ-META-001",
            "title": "Missing Meta Description",
            "severity": "medium",
            "evidence": (
                f"Page at '{url}' has no <meta name=\"description\"> tag. "
                "AI answer engines and search previews rely on meta descriptions "
                "to determine context and relevance."
            ),
            "suggested_action": {
                "summary": (
                    "Add a concise, accurate <meta name=\"description\"> (50-160 characters) "
                    "that summarises the page's primary topic and value proposition."
                ),
                "priority": "medium",
                "impact": "medium",
                "effort": "easy",
                "target_persona": "content_writer",
            },
        }
    if len(meta_desc) > 320:
        return {
            "rule_id": "CQ-META-OVERSIZED-001",
            "title": "Oversized Meta Description",
            "severity": "medium",
            "evidence": (
                f"Page at '{url}' has a meta description of {len(meta_desc)} characters "
                "(over the 320-character soft cap), which may be truncated by search engines "
                "and AI snippet generators."
            ),
            "suggested_action": {
                "summary": (
                    "Trim the meta description to 50-160 characters, "
                    "placing the most important context first."
                ),
                "priority": "medium",
                "impact": "low",
                "effort": "easy",
                "target_persona": "content_writer",
            },
        }
    return None


def _identity_context_matches(a, b):
    """Require stable page identity context before declaring exact duplicates."""
    def norm(value):
        return re.sub(r"\s+", " ", str(value or "").strip().lower())

    a_title = norm(a.get("title"))
    b_title = norm(b.get("title"))
    a_role = norm(a.get("page_role"))
    b_role = norm(b.get("page_role"))
    if a_title and b_title and a_title != b_title:
        return False
    if a_role and b_role and a_role != b_role:
        return False
    return True


# ---------------------------------------------------------------------------
# Cross-page checks
# ---------------------------------------------------------------------------
def _check_duplicates_and_overlap(page_data):
    """
    page_data: list of dicts with keys: url, norm_text, body_hash, shingles, term_set

    Returns list of findings.
    """
    findings = []
    n = len(page_data)
    if n < 2:
        return findings

    reported_pairs = set()  # frozenset of {url_a, url_b}

    for i in range(n):
        a = page_data[i]
        for j in range(i + 1, n):
            b = page_data[j]
            a_final = (a.get("final_url") or a.get("url") or "").strip()
            b_final = (b.get("final_url") or b.get("url") or "").strip()
            # Never compare two requested URLs that resolved to the same resource.
            if a_final and b_final and a_final == b_final:
                continue

            pair_key = frozenset({a["url"], b["url"]})
            if pair_key in reported_pairs:
                continue

            # Exact duplicate requires enough substantive text and matching page identity context.
            if (a["body_hash"] and b["body_hash"] and a["body_hash"] == b["body_hash"]
                    and len(a.get("norm_text", "").split()) >= 8
                    and len(b.get("norm_text", "").split()) >= 8
                    and _identity_context_matches(a, b)):
                reported_pairs.add(pair_key)
                findings.append({
                    "rule_id": "CQ-EXACT-DUP-001",
                    "title": "Exact Duplicate Content Detected",
                    "severity": "high",
                    "evidence": (
                        f"Pages at '{a['url']}' and '{b['url']}' produce "
                        "identical normalised substantive body text (SHA-256 match). "
                        "Exact duplicate pages can dilute AI answer confidence and "
                        "prevent clear source attribution."
                    ),
                    "suggested_action": {
                        "summary": (
                            "Consolidate duplicate pages using a canonical tag, "
                            "301 redirect, or by differentiating the content on each URL."
                        ),
                        "priority": "high",
                        "impact": "high",
                        "effort": "medium",
                        "target_persona": "seo_team",
                    },
                    "content_quality_detail": {
                        "similarity": 1.0,
                        "method": "sha256_exact",
                        "affected_urls": [a["url"], b["url"]],
                    },
                })
                continue

            # 2. Near-duplicate (sequence similarity / body shingles)
            seq_sim = 0.0
            if a["norm_text"] and b["norm_text"]:
                sample_a = a["norm_text"][:2000]
                sample_b = b["norm_text"][:2000]
                seq_sim = difflib.SequenceMatcher(None, sample_a, sample_b).ratio()

            shingle_jac = 0.0
            if a["shingles"] and b["shingles"]:
                shingle_jac = _jaccard(a["shingles"], b["shingles"])

            sim_score = max(seq_sim, shingle_jac)

            if sim_score >= NEAR_DUP_JACCARD or seq_sim >= 0.80:
                reported_pairs.add(pair_key)
                findings.append({
                    "rule_id": "CQ-NEAR-DUP-001",
                    "title": "Near-Duplicate Content Detected",
                    "severity": "medium",
                    "evidence": (
                        f"Pages at '{a['url']}' and '{b['url']}' share "
                        f"approximately {sim_score:.0%} substantive text similarity. "
                        "Near-duplicate pages risk confusing AI systems about which URL "
                        "is the primary source."
                    ),
                    "suggested_action": {
                        "summary": (
                            "Differentiate the content on these pages or consolidate them "
                            "with a canonical tag pointing to the preferred version."
                        ),
                        "priority": "medium",
                        "impact": "medium",
                        "effort": "medium",
                        "target_persona": "content_writer",
                    },
                    "content_quality_detail": {
                        "similarity": round(sim_score, 3),
                        "method": "char_ngram_jaccard",
                        "affected_urls": [a["url"], b["url"]],
                    },
                })
                continue

            # 3. Potential topic overlap (term Jaccard)
            if a["term_set"] and b["term_set"]:
                term_jac = _jaccard(a["term_set"], b["term_set"])
                if term_jac >= TOPIC_OVERLAP_JACCARD and pair_key not in reported_pairs:
                    reported_pairs.add(pair_key)
                    findings.append({
                        "rule_id": "CQ-TOPIC-OVERLAP-001",
                        "title": "Potential Topic Overlap Between Pages",
                        "severity": "medium",
                        "evidence": (
                            f"Pages at '{a['url']}' and '{b['url']}' share "
                            f"approximately {term_jac:.0%} top-term overlap. "
                            "This may indicate that both pages target the same topic, "
                            "which can create ambiguity for AI systems choosing between sources. "
                            "(Note: this signal requires review — shared navigation/footer terms "
                            "or same-category pages may legitimately share vocabulary.)"
                        ),
                        "suggested_action": {
                            "summary": (
                                "Review whether these pages serve distinct user intents. "
                                "If overlapping, differentiate focus topics, merge, or "
                                "use canonical tags to indicate the primary version."
                            ),
                            "priority": "medium",
                            "impact": "medium",
                            "effort": "medium",
                            "target_persona": "content_writer",
                        },
                        "content_quality_detail": {
                            "similarity": round(term_jac, 3),
                            "method": "term_jaccard",
                            "affected_urls": [a["url"], b["url"]],
                        },
                    })

    return findings


# ---------------------------------------------------------------------------
# Public entrypoint
# ---------------------------------------------------------------------------
def audit(artifact):
    """
    Standard detector entrypoint.

    Can be called in two modes:
    1. Single-page mode: artifact = {url, html, page_role}
    2. Multi-page mode: artifact = {page_artifacts: [{url, html, page_role}, ...]}

    Returns {"findings": [...]}
    """
    page_artifacts = artifact.get("page_artifacts")
    if not page_artifacts:
        # Single-page wrapper
        page_artifacts = [artifact]

    findings = []
    page_data = []

    for page in page_artifacts:
        url = page.get("url", "")
        html = page.get("html", "") or ""
        page_role = page.get("page_role") or page.get("inferred_role") or "general"
        is_soft_blocked = page.get("is_soft_blocked", False)
        extraction_uncertain = page.get("extraction_uncertain", False)

        fetch_mode = page.get("fetch_mode", "")
        status_code = page.get("status_code", 200)
        content_type = (page.get("content_type") or "").lower()

        # Soft-block is itself a positive evidence-backed finding. Emit it before
        # generic uncertainty suppression, then suppress all content-absence cascades.
        if is_soft_blocked:
            findings.append({
                "rule_id": "CQ-SOFT-BLOCK-001",
                "title": "Page Content Unverifiable (Soft-Block/Challenge Detected)",
                "severity": "medium",
                "evidence": (
                    f"Page at '{url}' returned an anti-bot challenge, CAPTCHA, or soft-block response (HTTP 200). "
                    "Substantive content analysis was suppressed because page body reflects an access challenge rather than actual content."
                ),
                "suggested_action": {
                    "summary": "Configure crawler access allowances or review anti-bot rules to permit automated AI readiness auditing.",
                    "priority": "medium",
                    "impact": "medium",
                    "effort": "medium",
                    "target_persona": "devops",
                },
                "source_url": url,
            })
            continue

        # Requirement 6 & 13: For failed fetches, unrendered SPA shells, or non-HTML pages, do not emit false absence findings
        if (page.get("is_spa_shell") or extraction_uncertain
                or fetch_mode in ("unsupported_content_type", "fetch_failed", "blocked")
                or (status_code and status_code != 200)):
            continue
        if content_type and not ("text/html" in content_type or "application/xhtml" in content_type):
            continue

        # Single-page checks
        thin_finding = _check_thin_content(url, html, page_role)
        if thin_finding:
            thin_finding["source_url"] = url
            findings.append(thin_finding)

        meta_finding = _check_meta_description(url, html)
        if meta_finding:
            meta_finding["source_url"] = url
            findings.append(meta_finding)

        # Prepare per-page substantive main content for cross-page checks
        substantive_text = _visible_text(html)
        norm = _normalise_body(substantive_text)
        page_data.append({
            "url": url,
            "requested_url": page.get("requested_url", url),
            "final_url": page.get("final_url", page.get("url", url)),
            "title": page.get("title", ""),
            "page_role": page.get("page_role", ""),
            "norm_text": norm,
            "body_hash": _body_hash(norm) if norm else "",
            "shingles": _shingles(norm) if len(norm) >= SHINGLE_SIZE else frozenset(),
            "term_set": _top_terms(norm),
        })

    # Cross-page checks (only meaningful with 2+ pages)
    cross_findings = _check_duplicates_and_overlap(page_data)
    findings.extend(cross_findings)

    return {"findings": findings}
