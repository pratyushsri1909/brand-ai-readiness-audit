import json
from html.parser import HTMLParser
import re


class JsonLdExtractor(HTMLParser):
    def __init__(self):
        super().__init__()
        self.blocks = []
        self._in_script = False
        self._is_jsonld = False
        self._current_data = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "script":
            d = dict(attrs)
            t = (d.get("type") or "").lower()
            if t == "application/ld+json":
                self._in_script = True
                self._is_jsonld = True
                self._current_data = []

    def handle_endtag(self, tag):
        if tag.lower() == "script" and self._in_script:
            if self._is_jsonld and self._current_data:
                self.blocks.append("".join(self._current_data))
            self._in_script = False
            self._is_jsonld = False
            self._current_data = []

    def handle_data(self, data):
        if self._in_script and self._is_jsonld:
            self._current_data.append(data)


def parse_page_entities(html):
    """Extracts all JSON-LD dict objects from HTML."""
    extractor = JsonLdExtractor()
    extractor.feed(html or "")
    objects = []
    for b in extractor.blocks:
        try:
            val = json.loads(b.strip())
            if isinstance(val, dict):
                graph = val.get("@graph")
                if isinstance(graph, list):
                    objects.extend(item for item in graph if isinstance(item, dict))
                else:
                    objects.append(val)
            elif isinstance(val, list):
                objects.extend(item for item in val if isinstance(item, dict))
        except Exception:
            continue
    return objects


def audit_cross_page_entities(page_artifacts):
    """
    Evaluates consistency across multiple page artifacts:
    - Organization identity consistency (name, @id, url)
    - Distinguishes CONFLICTING (same identity disagrees with itself) vs AMBIGUOUS (multi-brand)
    - Product price consistency for matching product names
    """
    findings = []
    if len(page_artifacts) < 2:
        return findings

    # Identity tracking: keyed by identity identifier (@id or normalized url)
    org_identities = {}
    products_by_name = {}

    for page in page_artifacts:
        url = page.get("url", "")
        html = page.get("html", "")
        objs = parse_page_entities(html)

        for obj in objs:
            obj_type = obj.get("@type")
            types = set(obj_type if isinstance(obj_type, list) else [obj_type])

            if "Organization" in types:
                org_id = obj.get("@id") or obj.get("url")
                name = str(obj.get("name") or "").strip()
                org_url = str(obj.get("url") or "").strip()

                if org_id:
                    key = str(org_id).strip()
                    org_identities.setdefault(key, []).append({
                        "page_url": url,
                        "name": name,
                        "url": org_url,
                        "@id": org_id,
                    })

            if "Product" in types:
                p_name = str(obj.get("name") or "").strip()
                offers = obj.get("offers")
                price = None
                if isinstance(offers, dict):
                    price = str(offers.get("price") or "").strip()
                elif isinstance(offers, list) and offers:
                    first = offers[0]
                    if isinstance(first, dict):
                        price = str(first.get("price") or "").strip()
                if p_name and price:
                    products_by_name.setdefault(p_name.lower(), []).append({
                        "page_url": url,
                        "name": p_name,
                        "price": price,
                    })

    # 1. Check for true self-contradiction on Organization identity
    for ident_key, instances in org_identities.items():
        names = {inst["name"] for inst in instances if inst["name"]}
        if len(names) > 1:
            urls = [inst["page_url"] for inst in instances]
            findings.append({
                "rule_id": "ENT-CONFLICT-NAME-001",
                "title": "Conflicting Organization Names Across Pages",
                "severity": "high",
                "evidence": f"Declared identity '{ident_key}' uses contradictory names ({', '.join(repr(n) for n in sorted(names))}) across sampled pages: {', '.join(urls[:3])}.",
                "suggested_action": {
                    "summary": "Standardize the organization name across all JSON-LD declarations referencing this entity ID.",
                    "priority": "high",
                },
            })

    # 2. Check for conflicting product pricing on the same product
    for prod_lower, instances in products_by_name.items():
        prices = {inst["price"] for inst in instances if inst["price"]}
        if len(prices) > 1:
            urls = [inst["page_url"] for inst in instances]
            first_name = instances[0]["name"]
            findings.append({
                "rule_id": "ENT-CONFLICT-PRICE-001",
                "title": "Conflicting Product Pricing Across Pages",
                "severity": "high",
                "evidence": f"Product '{first_name}' advertises contradictory prices ({', '.join(sorted(prices))}) across sampled pages: {', '.join(urls[:3])}.",
                "suggested_action": {
                    "summary": "Synchronize product pricing across promotional, listing, and detail pages to prevent inaccurate AI quotation.",
                    "priority": "high",
                },
            })

    return findings


def audit(artifact):
    """
    Standard detector entrypoint for entity-corroboration-audit.
    Can receive either a single artifact or a dict containing page_artifacts list.
    """
    page_artifacts = artifact.get("page_artifacts", [])
    if not page_artifacts:
        # If single page passed in standard detector pattern
        page_artifacts = [artifact]

    findings = audit_cross_page_entities(page_artifacts)
    return {"findings": findings}
