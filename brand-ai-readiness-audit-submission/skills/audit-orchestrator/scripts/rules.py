import json
import re

RULE_REGISTRY = {
    "CR-BUDGET-001": {
        "title_pattern": r"Runtime Budget Exhausted",
        "default_severity": "medium",
        "root_cause": "The audit runtime budget was exhausted before the requested evidence could be fully collected.",
        "expected_mechanism": "Keeping audit work within a bounded runtime allows deterministic completion without unbounded crawler execution.",
        "impact": "medium",
        "effort": "medium",
        "target_persona": "developer",
        "confidence": "measured",
        "remediation_id": "REM-CRAWL-001",
        "snippet_eligible": False,
    },
    "CR-REDIRECT-CHAIN-001": {
        "title_pattern": r"Redirect Chain Adds Multiple Navigation Hops",
        "default_severity": "medium",
        "root_cause": "The requested URL followed multiple HTTP redirect hops before reaching a final destination.",
        "expected_mechanism": "Reduce unnecessary redirect hops and point internal references directly to the canonical destination.",
        "impact": "medium",
        "effort": "easy",
        "target_persona": "developer",
        "confidence": "measured",
        "remediation_id": "REM-REDIR-001",
        "snippet_eligible": False,
    },
    "CR-STATUS-001": {
        "title_pattern": r"Target Page (?:Fetch Failed|Returned)",
        "default_severity": "high",
        "root_cause": "The server responded with an error HTTP status code or connection failure, preventing crawler access.",
        "expected_mechanism": "Resolving server availability enables search engine bots and AI answer engines to fetch page contents reliably.",
        "impact": "high",
        "effort": "easy",
        "target_persona": "developer",
        "confidence": "measured",
        "remediation_id": "REM-SRV-001",
        "snippet_eligible": False,
    },
    "CR-ROBOTS-001": {
        "title_pattern": r"Content Blocked by robots\.txt",
        "default_severity": "critical",
        "root_cause": "The site robots.txt policy explicitly disallows automated agents from crawling the target URI.",
        "expected_mechanism": "Updating robots.txt permits automated retrieval and indexing by AI discovery agents.",
        "impact": "high",
        "effort": "easy",
        "target_persona": "developer",
        "confidence": "measured",
        "remediation_id": "REM-ROB-001",
        "snippet_eligible": True,
        "snippet_type": "robots_txt",
    },
    "CR-ROBOTS-002": {
        "title_pattern": r"Redirect Target Blocked by robots\.txt",
        "default_severity": "high",
        "root_cause": "A redirect hop led to a target origin whose robots.txt policy prohibits crawling.",
        "expected_mechanism": "Permitting crawler access on all redirect targets ensures unhindered multi-hop indexing.",
        "impact": "high",
        "effort": "easy",
        "target_persona": "developer",
        "confidence": "measured",
        "remediation_id": "REM-ROB-002",
        "snippet_eligible": False,
    },
    "CR-ROBOTS-003": {
        "title_pattern": r"Unable to Verify robots\.txt Safety",
        "default_severity": "high",
        "root_cause": "The robots.txt endpoint returned an ambiguous or failing status (e.g. 5xx, 403, or timeout), halting safe crawl.",
        "expected_mechanism": "Restoring a reachable robots.txt (200 or 404) allows crawlers to deterministically verify permissions.",
        "impact": "high",
        "effort": "easy",
        "target_persona": "developer",
        "confidence": "measured",
        "remediation_id": "REM-ROB-003",
        "snippet_eligible": False,
    },
    "CR-NOINDEX-001": {
        "title_pattern": r"Noindex Directive Blocks Machine Indexing",
        "default_severity": "critical",
        "root_cause": "A page-level meta tag or X-Robots-Tag header explicitly commands crawlers not to index this document.",
        "expected_mechanism": "Removing noindex allows language models and indexers to ingest and cite page content.",
        "impact": "high",
        "effort": "easy",
        "target_persona": "developer",
        "confidence": "measured",
        "remediation_id": "REM-IDX-001",
        "snippet_eligible": True,
        "snippet_type": "meta_robots",
    },
    "CR-NOFOLLOW-001": {
        "title_pattern": r"Nofollow Directive Restricts Link Traversal",
        "default_severity": "medium",
        "root_cause": "A nofollow directive commands crawlers not to follow outgoing links on the page.",
        "expected_mechanism": "Removing nofollow allows machine crawlers to discover linked brand assets and subpages.",
        "impact": "medium",
        "effort": "easy",
        "target_persona": "seo_team",
        "confidence": "measured",
        "remediation_id": "REM-LNK-001",
        "snippet_eligible": False,
    },
    "CR-DIRECTIVE-CONFLICT-001": {
        "title_pattern": r"Conflicting Indexing Directives",
        "default_severity": "medium",
        "root_cause": "Contradictory directives (e.g. index alongside noindex) are specified across headers or meta tags.",
        "expected_mechanism": "Harmonizing crawl directives prevents unpredictable crawler behavior.",
        "impact": "medium",
        "effort": "easy",
        "target_persona": "developer",
        "confidence": "measured",
        "remediation_id": "REM-IDX-002",
        "snippet_eligible": False,
    },
    "CR-RENDER-SPA-001": {
        "title_pattern": r"Likely Client-Side Rendering Dependency",
        "default_severity": "high",
        "root_cause": "The page contains an empty SPA mount point with minimal initial raw HTML text, requiring client JS execution.",
        "expected_mechanism": "Pre-rendering or SSR provides complete HTML text to simple crawler bots without browser overhead.",
        "impact": "high",
        "effort": "hard",
        "target_persona": "developer",
        "confidence": "inferred",
        "remediation_id": "REM-RND-001",
        "snippet_eligible": False,
    },
    "CR-RENDER-HYDRATION-001": {
        "title_pattern": r"Likely JavaScript-Dependent Initial Content",
        "default_severity": "high",
        "root_cause": "Hydration markers were found with sparse raw text, indicating content is assembled dynamically in client JS.",
        "expected_mechanism": "Server-side hydration ensures primary text facts are present in the initial TCP payload.",
        "impact": "high",
        "effort": "hard",
        "target_persona": "developer",
        "confidence": "inferred",
        "remediation_id": "REM-RND-002",
        "snippet_eligible": False,
    },
    "CR-RENDER-SCRIPTHEAVY-001": {
        "title_pattern": r"Script-Heavy Page With Limited Raw Text",
        "default_severity": "medium",
        "root_cause": "Script bytes dominate the HTML payload while readable text volume is minimal.",
        "expected_mechanism": "Reducing initial script weight ensures crawlers quickly extract core content.",
        "impact": "medium",
        "effort": "medium",
        "target_persona": "developer",
        "confidence": "inferred",
        "remediation_id": "REM-RND-003",
        "snippet_eligible": False,
    },
    "CR-RENDER-MIN-001": {
        "title_pattern": r"Minimal Initial HTML Content Density",
        "default_severity": "medium",
        "root_cause": "The initial static HTML contains minimal textual information, potentially obscuring content from HTTP-only crawlers.",
        "expected_mechanism": "Delivering complete content in the initial HTML ensures discoverability by simple non-browser HTTP crawlers and AI bots.",
        "impact": "medium",
        "effort": "medium",
        "target_persona": "developer",
        "confidence": "inferred",
        "remediation_id": "REM-RND-002",
        "snippet_eligible": False,
    },
    "CR-RENDER-GAP-001": {
        "title_pattern": r"Rendered Content Exceeds Raw HTML Content",
        "default_severity": "high",
        "root_cause": "A substantial text volume appears only after client browser JavaScript execution.",
        "expected_mechanism": "Delivering complete content in the initial HTML enables discovery by non-browser AI bots and simple indexers.",
        "impact": "high",
        "effort": "hard",
        "target_persona": "developer",
        "confidence": "measured",
        "remediation_id": "REM-RND-004",
        "snippet_eligible": False,
    },
    "SD-SYNTAX-001": {
        "title_pattern": r"Malformed JSON-LD Syntax",
        "default_severity": "high",
        "root_cause": "A JSON-LD script block contains malformed JSON syntax and cannot be parsed by machine consumers.",
        "expected_mechanism": "Fixing syntax enables search engines and LLMs to ingest Schema.org facts without parsing errors.",
        "impact": "high",
        "effort": "easy",
        "target_persona": "developer",
        "confidence": "measured",
        "remediation_id": "REM-SCH-001",
        "snippet_eligible": False,
    },
    "SD-MISSING-001": {
        "title_pattern": r"Missing JSON-LD Structured Data",
        "default_severity": "high",
        "root_cause": "No application/ld+json block was found in the initial HTML response.",
        "expected_mechanism": "Publishing Schema.org JSON-LD structured data provides explicit entity context to machine engines.",
        "impact": "high",
        "effort": "easy",
        "target_persona": "developer",
        "confidence": "measured",
        "remediation_id": "REM-SCH-002",
        "snippet_eligible": True,
        "snippet_type": "jsonld_org",
    },
    "SD-COMMERCE-001": {
        "title_pattern": r"Missing Product/Offer Structured Data",
        "default_severity": "high",
        "root_cause": "The page displays commerce signals (pricing, CTA, cart) but lacks Schema.org Product or Offer markup.",
        "expected_mechanism": "Adding Product/Offer markup allows AI shopping assistants to accurately cite pricing, availability, and specs.",
        "impact": "high",
        "effort": "medium",
        "target_persona": "developer",
        "confidence": "inferred",
        "remediation_id": "REM-SCH-003",
        "snippet_eligible": True,
        "snippet_type": "jsonld_product",
    },
    "SD-ORG-ID-001": {
        "title_pattern": r"Organization Entity Lacks Definitive Disambiguation Signals",
        "default_severity": "medium",
        "root_cause": "Organization schema entities omit a global @id or sameAs links, reducing machine disambiguation clarity.",
        "expected_mechanism": "Providing URI-based @id and authoritative sameAs profiles enables knowledge graph reconciliation.",
        "impact": "medium",
        "effort": "easy",
        "target_persona": "developer",
        "confidence": "measured",
        "remediation_id": "REM-SCH-004",
        "snippet_eligible": True,
        "snippet_type": "jsonld_org_id",
    },
    "SD-ORG-HOST-001": {
        "title_pattern": r"Organization URL Conflicts With Canonical Host",
        "default_severity": "medium",
        "root_cause": "The declared Organization.url points to a different host than the page canonical URI.",
        "expected_mechanism": "Harmonizing Organization.url with the audited domain prevents multi-entity confusion.",
        "impact": "medium",
        "effort": "easy",
        "target_persona": "developer",
        "confidence": "measured",
        "remediation_id": "REM-SCH-005",
        "snippet_eligible": False,
    },
    "SD-FRESH-STALE-001": {
        "title_pattern": r"Potentially Stale Content / Outdated Freshness Signal",
        "default_severity": "medium",
        "root_cause": "The latest modification or publication timestamp exceeds the configured staleness threshold.",
        "expected_mechanism": "Updating dateModified and HTTP Last-Modified confirms facts are current to conversational AI agents.",
        "impact": "medium",
        "effort": "easy",
        "target_persona": "content_writer",
        "confidence": "measured",
        "remediation_id": "REM-FRESH-001",
        "snippet_eligible": False,
    },
    "SD-FRESH-FUTURE-001": {
        "title_pattern": r"Anomalous Future Publication Date",
        "default_severity": "medium",
        "root_cause": "Structured data timestamp is set into the future relative to the reference audit date.",
        "expected_mechanism": "Aligning timestamps with actual publication time restores temporal validity.",
        "impact": "low",
        "effort": "easy",
        "target_persona": "developer",
        "confidence": "measured",
        "remediation_id": "REM-FRESH-002",
        "snippet_eligible": False,
    },
    "SD-FRESH-CONTRADICT-001": {
        "title_pattern": r"Contradictory Publication and Modification Dates",
        "default_severity": "medium",
        "root_cause": "dateModified timestamp precedes datePublished in structured data.",
        "expected_mechanism": "Chronologically valid timestamps ensure AI agents trust the revision sequence.",
        "impact": "low",
        "effort": "easy",
        "target_persona": "developer",
        "confidence": "measured",
        "remediation_id": "REM-FRESH-003",
        "snippet_eligible": False,
    },
    "SD-FRESH-HEADER-CONFLICT-001": {
        "title_pattern": r"Conflicting Content Freshness Signals",
        "default_severity": "medium",
        "root_cause": "HTTP Last-Modified header diverges significantly from in-page dateModified.",
        "expected_mechanism": "Synchronizing HTTP and HTML date signals prevents conflicting cache decisions.",
        "impact": "medium",
        "effort": "easy",
        "target_persona": "developer",
        "confidence": "measured",
        "remediation_id": "REM-FRESH-004",
        "snippet_eligible": False,
    },
    "SD-FRESH-MISSING-001": {
        "title_pattern": r"Missing Freshness Signal",
        "default_severity": "medium",
        "root_cause": "An article-like entity lacks datePublished, dateModified, or Last-Modified headers.",
        "expected_mechanism": "Adding timestamps allows answer engines to assess factual recency and avoid temporal hallucinations.",
        "impact": "medium",
        "effort": "easy",
        "target_persona": "developer",
        "confidence": "measured",
        "remediation_id": "REM-FRESH-005",
        "snippet_eligible": True,
        "snippet_type": "jsonld_article_date",
    },
    "SD-FRESH-MALFORMED-001": {
        "title_pattern": r"Unparseable Content Timestamp in Structured Data",
        "default_severity": "medium",
        "root_cause": "A date string in structured data cannot be parsed by standard ISO-8601 parsers.",
        "expected_mechanism": "Formatting timestamps as ISO-8601 (YYYY-MM-DDThh:mm:ssZ) enables deterministic machine parsing.",
        "impact": "medium",
        "effort": "easy",
        "target_persona": "developer",
        "confidence": "measured",
        "remediation_id": "REM-FRESH-006",
        "snippet_eligible": False,
    },
    "SD-NONTEXT-001": {
        "title_pattern": r"(?:Substantive Visual Element Lacks Accessible Text|Critical Information Locked in|Information Locked in Canvas|Content Image Missing Alt Text|SVG Element Lacks Accessible Description)",
        "default_severity": "medium",
        "root_cause": "An image, canvas, or SVG graphic lacks alt text, title/desc, or accessible textual description.",
        "expected_mechanism": "Providing descriptive alt text, titles, or transcripts allows non-multimodal crawlers and AI search agents to ingest graphic data.",
        "impact": "medium",
        "effort": "easy",
        "target_persona": "content_writer",
        "confidence": "inferred",
        "remediation_id": "REM-ACC-001",
        "snippet_eligible": False,
    },
    "ENT-CONFLICT-NAME-001": {
        "title_pattern": r"Conflicting Organization Names Across (?:Sampled )?Pages",
        "default_severity": "high",
        "root_cause": "Sampled pages declare divergent or contradictory Organization entity names.",
        "expected_mechanism": "Aligning organization names across all pages establishes a unified identity in search entity graphs.",
        "impact": "high",
        "effort": "easy",
        "target_persona": "content_writer",
        "confidence": "measured",
        "remediation_id": "REM-ENT-001",
        "snippet_eligible": False,
    },
    "ENT-CONFLICT-PRICE-001": {
        "title_pattern": r"Conflicting Product Pricing Across (?:Sampled )?Pages",
        "default_severity": "high",
        "root_cause": "Different sampled pages state conflicting prices for the same product.",
        "expected_mechanism": "Synchronizing product pricing across promotional, listing, and detail pages prevents inaccurate AI quotation.",
        "impact": "high",
        "effort": "medium",
        "target_persona": "marketing",
        "confidence": "measured",
        "remediation_id": "REM-ENT-002",
        "snippet_eligible": False,
    },
    "ENT-CONFLICT-URL-001": {
        "title_pattern": r"Conflicting Organization URLs Across (?:Sampled )?Pages",
        "default_severity": "high",
        "root_cause": "Sampled pages declare divergent Organization URLs.",
        "expected_mechanism": "Aligning Organization.url across all structured data entities to point to the canonical brand domain ensures clear attribution.",
        "impact": "high",
        "effort": "easy",
        "target_persona": "developer",
        "confidence": "measured",
        "remediation_id": "REM-ENT-003",
        "snippet_eligible": False,
    },
    "ENG-H1-ZERO-001": {
        "title_pattern": r"Missing H1 Heading",
        "default_severity": "medium",
        "root_cause": "The page contains zero structural <h1> heading elements.",
        "expected_mechanism": "A single primary H1 establishes the definitive document topic for assistive tools and AI models.",
        "impact": "high",
        "effort": "easy",
        "target_persona": "content_writer",
        "confidence": "measured",
        "remediation_id": "REM-ENG-001",
        "snippet_eligible": True,
        "snippet_type": "html_h1",
    },
    "ENG-H1-MULTI-001": {
        "title_pattern": r"Multiple H1 Headings",
        "default_severity": "medium",
        "root_cause": "The document contains more than one <h1> element, diffusing top-level topic hierarchy.",
        "expected_mechanism": "Consolidating to a single primary H1 clarifies core entity focus.",
        "impact": "medium",
        "effort": "easy",
        "target_persona": "content_writer",
        "confidence": "measured",
        "remediation_id": "REM-ENG-002",
        "snippet_eligible": False,
    },
    "ENG-ORIENTATION-MISSING-001": {
        "title_pattern": r"Missing Page Orientation",
        "default_severity": "high",
        "root_cause": "Neither a non-empty <title> tag nor an <h1> element was found in the HTML.",
        "expected_mechanism": "Adding a title and primary H1 orient humans and AI agents immediately to the page purpose.",
        "impact": "high",
        "effort": "easy",
        "target_persona": "content_writer",
        "confidence": "measured",
        "remediation_id": "REM-ENG-003",
        "snippet_eligible": False,
    },
    "ENG-TITLE-GENERIC-001": {
        "title_pattern": r"Generic or Low-Information Page Title",
        "default_severity": "medium",
        "root_cause": "The title tag uses generic single-word labels (e.g. 'Home', 'Index') lacking entity context.",
        "expected_mechanism": "Enriching the title with specific entity and service names improves conversational search retrieval.",
        "impact": "medium",
        "effort": "easy",
        "target_persona": "content_writer",
        "confidence": "measured",
        "remediation_id": "REM-ENG-004",
        "snippet_eligible": False,
    },
    "ENG-CANONICAL-DIVERGENT-001": {
        "title_pattern": r"Conflicting Multiple Canonical Tags",
        "default_severity": "high",
        "root_cause": "Multiple canonical tags point to different target URLs.",
        "expected_mechanism": "A single unambiguous canonical tag ensures proper index consolidation.",
        "impact": "high",
        "effort": "easy",
        "target_persona": "developer",
        "confidence": "measured",
        "remediation_id": "REM-CAN-001",
        "snippet_eligible": False,
    },
    "ENG-CANONICAL-FRAG-001": {
        "title_pattern": r"Canonical Tag Contains URL Fragment",
        "default_severity": "medium",
        "root_cause": "The canonical URL contains a hash fragment, which search engines strip or flag as invalid.",
        "expected_mechanism": "Specifying fragment-free canonical URLs conforms to standard indexing protocols.",
        "impact": "medium",
        "effort": "easy",
        "target_persona": "developer",
        "confidence": "measured",
        "remediation_id": "REM-CAN-002",
        "snippet_eligible": False,
    },
    "ENG-CANONICAL-HOST-001": {
        "title_pattern": r"Cross-Domain Canonical Reference",
        "default_severity": "medium",
        "root_cause": "The canonical tag points to an external domain rather than the host being audited.",
        "expected_mechanism": "Pointing canonical tags to the self-hosted domain ensures original brand authority.",
        "impact": "medium",
        "effort": "easy",
        "target_persona": "seo_team",
        "confidence": "measured",
        "remediation_id": "REM-CAN-003",
        "snippet_eligible": False,
    },
    "ENG-SCANNABLE-001": {
        "title_pattern": r"Dense Text Block Impairs Scannability",
        "default_severity": "medium",
        "root_cause": "Paragraph blocks exceeding 800 characters without structural breaks reduce human readability.",
        "expected_mechanism": "Breaking dense text into subheadings and concise paragraphs improves human and AI summarization.",
        "impact": "medium",
        "effort": "easy",
        "target_persona": "content_writer",
        "confidence": "measured",
        "remediation_id": "REM-SCN-001",
        "snippet_eligible": False,
    },
    "ENG-NAV-DEADEND-001": {
        "title_pattern": r"Navigational Dead End",
        "default_severity": "high",
        "root_cause": "No internal navigation links exist to guide crawlers or users to related brand pages.",
        "expected_mechanism": "Adding contextual internal links allows users and agents to discover next steps in the customer journey.",
        "impact": "high",
        "effort": "easy",
        "target_persona": "content_writer",
        "confidence": "measured",
        "remediation_id": "REM-NAV-001",
        "snippet_eligible": False,
    },
    "ENG-CTA-MISSING-001": {
        "title_pattern": r"No Obvious Next Action / Missing Call-to-Action",
        "default_severity": "medium",
        "root_cause": "The page lacks identifiable call-to-action signals (buy, contact, start, demo, learn).",
        "expected_mechanism": "Clear interactive CTAs orient AI assistants when recommending direct user action.",
        "impact": "medium",
        "effort": "easy",
        "target_persona": "content_writer",
        "confidence": "measured",
        "remediation_id": "REM-CTA-001",
        "snippet_eligible": False,
    },
    "DISC-SITEMAP-MISSING-001": {
        "title_pattern": r"Missing or Inaccessible XML Sitemap",
        "default_severity": "medium",
        "root_cause": "No sitemap was declared in robots.txt and /sitemap.xml returned an inaccessible response.",
        "expected_mechanism": "Publishing an XML sitemap ensures complete discovery of deep catalog and content URLs.",
        "impact": "medium",
        "effort": "easy",
        "target_persona": "developer",
        "confidence": "measured",
        "remediation_id": "REM-DISC-001",
        "snippet_eligible": False,
    },
    "ENT-CONFLICT-NAME-001": {
        "title_pattern": r"Conflicting Organization Names Across Pages",
        "default_severity": "high",
        "root_cause": "Different sampled pages on the same site declare divergent Organization names for the same entity identity.",
        "expected_mechanism": "Consistent Organization naming across pages prevents brand identity ambiguity in knowledge graphs.",
        "impact": "high",
        "effort": "easy",
        "target_persona": "developer",
        "confidence": "measured",
        "remediation_id": "REM-ENT-001",
        "snippet_eligible": False,
    },
    "ENT-CONFLICT-PRICE-001": {
        "title_pattern": r"Conflicting Product Pricing Across Pages",
        "default_severity": "high",
        "root_cause": "The same product is advertised at contradictory price points across sampled internal pages.",
        "expected_mechanism": "Reconciling pricing across pages prevents shopping assistants from quoting inaccurate offer terms.",
        "impact": "high",
        "effort": "medium",
        "target_persona": "content_writer",
        "confidence": "measured",
        "remediation_id": "REM-ENT-002",
        "snippet_eligible": False,
    },
    "CQ-THIN-001": {
        "title_pattern": r"Thin Content Detected",
        "default_severity": "medium",
        "root_cause": "The substantive visible body copy does not satisfy the minimum word threshold for this page role.",
        "expected_mechanism": "Substantive, comprehensive body text allows AI assistants and indexers to ground answers on detailed facts.",
        "impact": "medium",
        "effort": "medium",
        "target_persona": "content_writer",
        "confidence": "measured",
        "remediation_id": "REM-CQ-001",
        "snippet_eligible": False,
    },
    "CQ-META-001": {
        "title_pattern": r"Missing Meta Description",
        "default_severity": "medium",
        "root_cause": "The page lacks a <meta name=\"description\"> summary tag.",
        "expected_mechanism": "Publishing a concise meta description provides a direct synopsis for answer engines and snippets.",
        "impact": "medium",
        "effort": "easy",
        "target_persona": "content_writer",
        "confidence": "measured",
        "remediation_id": "REM-CQ-002",
        "snippet_eligible": True,
        "snippet_type": "meta_description",
    },
    "CQ-META-OVERSIZED-001": {
        "title_pattern": r"Oversized Meta Description",
        "default_severity": "medium",
        "root_cause": "The meta description exceeds 300 characters and may be truncated or deprioritized by search models.",
        "expected_mechanism": "Targeting 50-160 characters ensures clean synopsis extraction without truncation.",
        "impact": "low",
        "effort": "easy",
        "target_persona": "content_writer",
        "confidence": "measured",
        "remediation_id": "REM-CQ-003",
        "snippet_eligible": False,
    },
    "CQ-EXACT-DUP-001": {
        "title_pattern": r"Exact Duplicate Content Detected",
        "default_severity": "high",
        "root_cause": "Multiple sampled URLs share identical substantive text (SHA-256 collision).",
        "expected_mechanism": "Consolidating identical content with canonical links or redirects prevents index dilution.",
        "impact": "high",
        "effort": "medium",
        "target_persona": "seo_team",
        "confidence": "measured",
        "remediation_id": "REM-CQ-004",
        "snippet_eligible": False,
    },
    "CQ-NEAR-DUP-001": {
        "title_pattern": r"Near-Duplicate Content Detected",
        "default_severity": "medium",
        "root_cause": "Different URLs share high textual sequence similarity (>= 80% ratio).",
        "expected_mechanism": "Differentiating content ensures unique intent representation for each page URL.",
        "impact": "medium",
        "effort": "medium",
        "target_persona": "content_writer",
        "confidence": "measured",
        "remediation_id": "REM-CQ-005",
        "snippet_eligible": False,
    },
    "CQ-TOPIC-OVERLAP-001": {
        "title_pattern": r"Potential Topic Overlap Between Pages",
        "default_severity": "medium",
        "root_cause": "Sampled pages exhibit high vocabulary Jaccard similarity across substantive terms.",
        "expected_mechanism": "Clarifying distinct focus topics avoids internal cannibalization in citation engines.",
        "impact": "medium",
        "effort": "medium",
        "target_persona": "content_writer",
        "confidence": "inferred",
        "remediation_id": "REM-CQ-006",
        "snippet_eligible": False,
    },
    "CQ-SOFT-BLOCK-001": {
        "title_pattern": r"Page Content Unverifiable \(Soft-Block/Challenge Detected\)",
        "default_severity": "medium",
        "root_cause": "The page returned an automated bot challenge, CAPTCHA, or verification wall over HTTP 200.",
        "expected_mechanism": "Whitelisting reputable AI crawlers allows automated brand readiness analysis without false blocks.",
        "impact": "medium",
        "effort": "medium",
        "target_persona": "devops",
        "confidence": "measured",
        "remediation_id": "REM-CQ-007",
        "snippet_eligible": False,
    },
    "ENG-CANONICAL-DUP-001": {
        "title_pattern": r"Duplicate Canonical Link Tags",
        "default_severity": "medium",
        "root_cause": "Multiple canonical link tags point redundantly to the same destination URL.",
        "expected_mechanism": "Maintaining exactly one canonical link element prevents HTML parser ambiguity.",
        "impact": "low",
        "effort": "easy",
        "target_persona": "developer",
        "confidence": "measured",
        "remediation_id": "REM-CAN-004",
        "snippet_eligible": False,
    },
    "SD-ORG-DUPLICATE-001": {
        "title_pattern": r"Ambiguous Duplicate Organization Entities",
        "default_severity": "medium",
        "root_cause": "Multiple Organization schema definitions omit stable @id URI anchors.",
        "expected_mechanism": "Consolidating to a single primary Organization with a permanent @id ensures deterministic identity.",
        "impact": "medium",
        "effort": "easy",
        "target_persona": "developer",
        "confidence": "measured",
        "remediation_id": "REM-SCH-006",
        "snippet_eligible": True,
        "snippet_type": "jsonld_org_id",
    },
    "DISC-INVALID-URL-001": {
        "title_pattern": r"Invalid Target URL",
        "default_severity": "critical",
        "root_cause": "The supplied target URL is not a well-formed absolute HTTP/HTTPS address.",
        "expected_mechanism": "Specifying a valid absolute URL allows network crawlers to resolve and reach the host.",
        "impact": "high",
        "effort": "easy",
        "target_persona": "developer",
        "confidence": "measured",
        "remediation_id": "REM-DISC-002",
        "snippet_eligible": False,
    },
    "DISC-BLOCKED-URL-001": {
        "title_pattern": r"Blocked Target URL",
        "default_severity": "critical",
        "root_cause": "The target URL resolves to an internal, private, or loopback network address.",
        "expected_mechanism": "Supplying a publicly resolvable hostname ensures compliance with SSRF safety constraints.",
        "impact": "high",
        "effort": "easy",
        "target_persona": "developer",
        "confidence": "measured",
        "remediation_id": "REM-DISC-003",
        "snippet_eligible": False,
    },
    "CR-DETECTOR-INCOMPLETE-001": {
        "title_pattern": r"Detector Execution Incomplete",
        "default_severity": "medium",
        "root_cause": "An isolated detector encountered unhandled markup exceptions and safely halted analysis.",
        "expected_mechanism": "Addressing malformed DOM tokens ensures complete multi-skill audit inspection.",
        "impact": "medium",
        "effort": "easy",
        "target_persona": "developer",
        "confidence": "measured",
        "remediation_id": "REM-SRV-002",
        "snippet_eligible": False,
    },
}

SEVERITY_WEIGHTS = {"critical": 4, "high": 3, "medium": 2}
CONFIDENCE_WEIGHTS = {"measured": 1.0, "inferred": 0.6, "uncertain": 0.4}

GENERIC_RULE_DEF = {
    "default_severity": "medium",
    "root_cause": "Identified quality or discoverability defect requires evaluation against web standards.",
    "expected_mechanism": "Addressing the underlying issue improves machine readability and human user experience.",
    "impact": "medium",
    "effort": "medium",
    "target_persona": "developer",
    "confidence": "inferred",
    "remediation_id": "REM-GEN-001",
    "snippet_eligible": False,
}


def match_rule_for_finding(finding_or_title):
    """
    Resolves a rule definition by machine-readable rule_id first.
    If a finding dict is provided with a rule_id, resolves directly from RULE_REGISTRY
    or safely falls back to generic rule without title regex matching.
    """
    if isinstance(finding_or_title, dict):
        rule_id = finding_or_title.get("rule_id")
        if rule_id:
            if rule_id in RULE_REGISTRY:
                return rule_id, RULE_REGISTRY[rule_id]
            # Unknown rule_id safely uses generic fallback
            return "GEN-AUDIT-001", GENERIC_RULE_DEF
        title = str(finding_or_title.get("title", "")).strip()
    else:
        title = str(finding_or_title or "").strip()

    # Direct match by rule_id if string matches a registry key
    if title in RULE_REGISTRY:
        return title, RULE_REGISTRY[title]

    # Isolated fallback for legacy title string invocations
    for rule_id, rule_def in RULE_REGISTRY.items():
        pattern = rule_def.get("title_pattern")
        if pattern and re.search(pattern, title, re.I):
            return rule_id, rule_def

    return "GEN-AUDIT-001", GENERIC_RULE_DEF


def generate_safe_snippet(rule_id, snippet_type, context):
    """
    Generates a deterministic slot-filled snippet validated for syntax.
    Returns a dict with snippet code, language, and label, or None if not eligible.
    All snippets strictly use placeholder tokens (<PRICE>, <CURRENCY>, <ORGANIZATION_NAME>)
    to avoid implying observed business values.
    """
    host = context.get("host", "<DOMAIN>")
    draft_label = "Example snippet only"

    if snippet_type == "meta_robots":
        code = '<meta name="robots" content="index, follow">'
        return {"language": "html", "code": code, "label": draft_label}

    elif snippet_type == "meta_description":
        code = '<meta name="description" content="Concise, factual synopsis of page topic and brand value proposition.">'
        return {"language": "html", "code": code, "label": draft_label}

    elif snippet_type == "robots_txt":
        code = f"# Robots.txt template for crawler discovery\nUser-agent: *\nAllow: /\nSitemap: https://{host}/sitemap.xml\n"
        return {"language": "plaintext", "code": code, "label": draft_label}

    elif snippet_type == "jsonld_org":
        snippet_dict = {
            "@context": "https://schema.org",
            "@type": "Organization",
            "@id": f"https://{host}/#organization",
            "name": "<ORGANIZATION_NAME>",
            "url": f"https://{host}",
        }
        code = json.dumps(snippet_dict, indent=2)
        json.loads(code)
        return {"language": "json", "code": f'<script type="application/ld+json">\n{code}\n</script>', "label": draft_label}

    elif snippet_type == "jsonld_product":
        snippet_dict = {
            "@context": "https://schema.org",
            "@type": "Product",
            "name": "<PRODUCT_NAME>",
            "offers": {
                "@type": "Offer",
                "priceCurrency": "<CURRENCY>",
                "price": "<PRICE>",
                "availability": "<AVAILABILITY_URL>",
            }
        }
        code = json.dumps(snippet_dict, indent=2)
        json.loads(code)
        return {"language": "json", "code": f'<script type="application/ld+json">\n{code}\n</script>', "label": draft_label}

    elif snippet_type == "jsonld_org_id":
        code = f'"@id": "https://{host}/#organization"'
        return {"language": "json", "code": code, "label": draft_label}

    elif snippet_type == "jsonld_article_date":
        code = '"datePublished": "<DATE_PUBLISHED>",\n"dateModified": "<DATE_MODIFIED>"'
        return {"language": "json", "code": code, "label": draft_label}

    elif snippet_type == "html_h1":
        code = '<h1><PRIMARY_PAGE_HEADING></h1>'
        return {"language": "html", "code": code, "label": draft_label}

    return None


def enrich_finding(raw_finding, context):
    """
    Enriches a finding with rule_id, root_cause, expected_mechanism, impact, effort,
    target_persona, confidence, provenance, priority ranking, and optional safe snippet.
    Uses rule_id as primary identity.
    """
    title = str(raw_finding.get("title", "")).strip()
    evidence = str(raw_finding.get("evidence", "")).strip()
    action = raw_finding.get("suggested_action") or {}

    rule_id = raw_finding.get("rule_id")
    if rule_id:
        if rule_id in RULE_REGISTRY:
            rule_def = RULE_REGISTRY[rule_id]
        else:
            rule_id = "GEN-AUDIT-001"
            rule_def = GENERIC_RULE_DEF
    else:
        rule_id, rule_def = match_rule_for_finding(raw_finding)

    severity = raw_finding.get("severity") or rule_def["default_severity"]
    severity = str(severity).lower()
    if severity not in {"critical", "high", "medium"}:
        severity = "medium"

    confidence = raw_finding.get("confidence") or rule_def.get("confidence", "measured")
    impact = action.get("impact") or rule_def.get("impact", "medium")
    effort = action.get("effort") or rule_def.get("effort", "easy")
    target_persona = action.get("target_persona") or rule_def.get("target_persona", "developer")

    # Priority ranking calculation: severity_weight * confidence_weight
    s_weight = SEVERITY_WEIGHTS.get(severity, 2)
    c_weight = CONFIDENCE_WEIGHTS.get(confidence, 1.0)
    priority_score = round(s_weight * c_weight, 2)

    # Keep priority string standard for schema compatibility
    priority_label = severity

    # Safe snippet generation
    snippet = None
    if rule_def.get("snippet_eligible") and rule_def.get("snippet_type"):
        try:
            snippet = generate_safe_snippet(rule_id, rule_def["snippet_type"], context)
        except Exception:
            snippet = None

    source_url = context.get("url") or raw_finding.get("source_url", "")
    detector_name = context.get("detector") or raw_finding.get("detector", "audit-orchestrator")
    page_role = context.get("page_role", "general")

    root_cause = rule_def["root_cause"]
    expected_mechanism = rule_def["expected_mechanism"]
    if rule_id == "CR-ROBOTS-003" and "robots_error_detail" in raw_finding:
        detail = raw_finding["robots_error_detail"].lower()
        root_cause = f"The robots.txt verification failed directly due to a {detail}."
        expected_mechanism = f"Resolve the {detail} so that the robots.txt endpoint can be safely verified by crawlers."

    enriched = {
        "title": title,
        "severity": severity,
        "evidence": evidence,
        "suggested_action": {
            "summary": str(action.get("summary", expected_mechanism)),
            "priority": priority_label,
        },
        "rule_id": rule_id,
        "root_cause": root_cause,
        "expected_mechanism": expected_mechanism,
        "impact": impact,
        "effort": effort,
        "target_persona": target_persona,
        "confidence": confidence,
        "remediation_id": rule_def["remediation_id"],
        "priority_score": priority_score,
        "provenance": {
            "source_url": source_url,
            "detector": detector_name,
            "page_role": page_role,
            "timestamp": context.get("audited_at", ""),
        },
    }

    if snippet:
        enriched["implementation"] = snippet

    return enriched


def generate_proactive_recommendations(page_artifacts, context):
    """
    Generates conservative, evidence-gated proactive recommendations with full metadata.
    """
    proactive = []
    host = context.get("host", "")

    for art in page_artifacts:
        html = str(art.get("html", "") or "")
        url = str(art.get("url", "") or "")

        # 1. FAQ schema opportunity: only when page has real Q&A patterns
        has_qa_dt_dd = bool(re.search(r'<dt\b[^>]*>.*?</dt>\s*<dd\b', html, re.I | re.S))
        has_question_headings = bool(re.search(r'<h[234]\b[^>]*>[^<]*\?[^<]*</h[234]>', html, re.I))
        has_faq_schema = bool(re.search(r'["\']@type["\']\s*:\s*["\']FAQPage["\']', html, re.I))

        if (has_qa_dt_dd or has_question_headings) and not has_faq_schema:
            proactive.append({
                "recommendation_id": "PRO-FAQ-001",
                "id": "PRO-FAQ-001",
                "title": "Proactive Opportunity: Add FAQPage Structured Data",
                "severity": "medium",
                "priority": "medium",
                "priority_score": 2.0,
                "impact": "medium",
                "effort": "easy",
                "target_persona": "developer",
                "evidence": f"Page at '{url}' contains question-and-answer formatted sections without Schema.org FAQPage structured data.",
                "evidence_refs": [url],
                "root_cause": "FAQ section lacks machine-readable JSON-LD markup.",
                "suggested_action": {
                    "summary": "Where genuine FAQ content exists, consider Schema.org FAQPage structured data to expose question/answer pairs in a machine-readable format, keeping markup synchronized with visible content.",
                    "priority": "medium",
                },
                "expected_mechanism": "Directly exposes question/answer pairs in a machine-readable format for search engines and AI assistants.",
                "confidence": "inferred",
                "remediation_id": "REM-SCH-005",
                "provenance": {
                    "source_url": url,
                    "detector": "rules-engine",
                    "timestamp": context.get("audited_at", ""),
                },
            })
            break

        # 2. Proactive Entity Disambiguation: Page has Organization but lacks sameAs social/authoritative profiles
        has_org = bool(re.search(r'["\']@type["\']\s*:\s*["\']Organization["\']', html, re.I))
        has_same_as = bool(re.search(r'["\']sameAs["\']\s*:', html, re.I))
        if has_org and not has_same_as:
            proactive.append({
                "recommendation_id": "PRO-ENT-001",
                "id": "PRO-ENT-001",
                "title": "Proactive Opportunity: Add Authoritative sameAs Profiles",
                "severity": "medium",
                "priority": "medium",
                "priority_score": 2.0,
                "impact": "medium",
                "effort": "easy",
                "target_persona": "seo_team",
                "evidence": f"Organization entity declared at '{url}' does not list external authority links (such as Wikidata, Wikipedia, or official social profiles).",
                "evidence_refs": [url],
                "root_cause": "Organization schema omits sameAs disambiguation properties.",
                "suggested_action": {
                    "summary": "Add sameAs array linking to official Wikidata, Crunchbase, or corporate social handles to reinforce entity resolution.",
                    "priority": "medium",
                },
                "expected_mechanism": "Explicit sameAs references assist automated systems in reconciling the brand against known entity profiles.",
                "confidence": "measured",
                "remediation_id": "REM-ENT-002",
                "provenance": {
                    "source_url": url,
                    "detector": "rules-engine",
                    "timestamp": context.get("audited_at", ""),
                },
            })
            break

    return proactive

