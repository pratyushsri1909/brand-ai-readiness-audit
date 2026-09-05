# PROJECT CONTEXT

## PROJECT
Adobe University Hackathon 2026 - Round 3: Agent Skill Marketplace

## OFFICIAL REQUIREMENTS
- Audit websites for AI discoverability and on-site engagement.
- Provide read-only, recommend-only assessments without modifying live sites.
- Package as an Agent Skill Marketplace with a marketplace.json manifest and exactly one entrypoint skill.
- Generalize to unseen websites without hardcoded example domains.
- Emit findings with severity, evidence, and prioritized suggested actions in the required report shape.
- Target runtime under 5 minutes for a typical website.
- Final ZIP must be at or below 50 MB.

## FINAL ARCHITECTURE
The marketplace contains one entrypoint and six focused detector skills (7 total skills). The orchestrator owns the shared network fetch and passes the resulting artifacts to each detector so the site is not redundantly crawled.

## CURRENT IMPLEMENTATION
- `audit-orchestrator`: bounded shared fetch, SSRF protection, robots enforcement, detector composition, finding deduplication, severity normalization, schema validation, and CLI entrypoint.
- `crawl-render-audit`: HTTP/robots policy, target reachability, raw-content readability, and static JS-render inference.
- `structured-data-freshness`: robust JSON-LD parsing, Product/Offer detection, freshness, and deterministic on-site entity identity checks.
- `engagement-audit`: title/H1 structure, scannability, navigation, and CTA/orientation heuristics.
- `site-discovery-audit`: robots.txt/sitemap discovery, URL normalization and role classification, representative page plan assembly within budget constraints.
- `entity-corroboration-audit`: cross-page Organization identity consistency, product price corroboration, strictly on-site deterministic signals with zero external lookups.
- `content-quality-audit`: thin content analysis with page-role thresholds, exact duplicates (SHA-256), near-duplicates (sequence and shingle Jaccard), topic overlap, and meta description validation.

## IMPORTANT SAFETY DECISIONS
- SSRF safety guard: Rejects private/loopback/link-local IPs (RFC 1918, RFC 4193, 169.254.169.254) and invalid schemes before issuing network requests.
- HTTP 404 for `robots.txt` means no robots rules were published; 403, 429, 5xx, timeouts, and network failures are treated as unsafe-to-crawl and halt the page fetch.
- The target page is fetched only after robots policy permits it.
- The implementation never claims to have executed a browser. Static JS signals are labeled as inference.
- Malformed JSON-LD and scalar JSON-LD values are isolated so one bad script cannot suppress valid structured data elsewhere on the page.
- Product/Offer warnings require overlapping commerce evidence instead of a currency symbol alone.
- Entity checks are limited to deterministic on-site corroboration; no external `sameAs` URLs are resolved.

## VALIDATION
The repository includes deterministic local fixtures and an executable validator. The test suite exercises both individual detectors and the actual CLI path.


## FINAL QA FIX
- Independent red-team QA reproduced a cross-origin redirect robots.txt bypass. Fixed in `audit-orchestrator/scripts/run_audit.py` by disabling automatic redirects, manually following up to 5 redirects, checking robots.txt for every redirect target origin, and reporting the final host from the final URL.
- Added regression tests for blocked and allowed cross-origin redirect targets.
- Local verification at that point: 115 tests passed; marketplace validator passed.

## CTA DETECTION FIX (follow-up QA round)
- Independent red-team QA found that `engagement-audit`'s CTA detector (`skills/engagement-audit/scripts/detector.py`) only scanned HTML attribute values (class/id/aria-label/etc.) for CTA vocabulary, never the visible text inside `<button>`/`<a>`. A plain `<button>Buy Now</button>` with no matching attribute was incorrectly reported as having no obvious next action.
- Fixed by accumulating visible text for `<a>`/`<button>` between their start and end tags (mirroring the existing `<h1>` text-accumulation pattern) and checking the combined attribute + text blob against the CTA vocabulary on the end tag. `<input>` (a void element) is checked at start-tag time using its attributes, since it has no separate end tag or text content.
- The CTA keyword regex was changed to use word-boundary matching (`\b(?:buy|cart|contact|learn|start|sign|shop|book|demo|quote)\b`) so that extending the check to free-form visible text does not introduce new false positives on ordinary words that merely contain a keyword as a substring (e.g. "Cartoons", "Bookshelf", "Startup", "Shopify").
- No other engagement heuristic (internal-link/navigation detection, paragraph scannability) had the same blind spot; navigation is intentionally href-based by design, and scannability already read visible paragraph text.
- Added `tests/test_engagement_cta.py` (8 new tests) covering: plain-text button CTA, plain-text anchor CTA, `<input value=...>` CTA, attribute-based CTA (regression guard), no-CTA case, the false-positive guard (ordinary words must not trigger), case-insensitivity, and multiple CTAs on one page.
- Full local test suite after the fix: 123 tests passed (115 previous + 8 new), 0 failed, 0 errors. Marketplace validator: passed.
- No new dependency, no network behavior change, no architecture change, and no other skill's files were modified.

## SITE DISCOVERY & ENTITY CORROBORATION EXPANSION
- Added `site-discovery-audit` skill: deterministic sitemap and link-topology discovery, URL normalization (strip tracking params, lowercase scheme/host, resolve relatives), role classification (Homepage/About/Product/Contact/Category/Article) by pattern match, page-plan assembly with configurable budget cap, and a graceful fallback to homepage link extraction when no sitemap is available. Tests: `tests/test_site_discovery.py` (10 tests).
- Added `entity-corroboration-audit` skill: multi-page Organization identity consistency check (name conflicts across shared `@id`/`url` keys), Product price corroboration across sampled pages, AMBIGUOUS vs CONFLICTING distinction to avoid false positives on legitimate multi-brand structures, zero external network requests. Tests: `tests/test_entity_corroboration.py`.

## CONTENT QUALITY AUDIT & SSRF PROTECTION (ROUND 3 FINAL)
- Added `content-quality-audit` skill: thin content detection with page-role specific word count thresholds, exact duplicate detection via body text SHA-256 hash matching, near-duplicate detection via sequence similarity & character shingle Jaccard, and topic overlap identification.
- Added robust pre-fetch SSRF protection in `audit-orchestrator/scripts/run_audit.py` to prevent access to private IP spaces, cloud metadata endpoints, loopback, and disallowed URI schemes without triggering blocking DNS queries.
- Added test coverage in `tests/test_content_quality.py` and `tests/test_ssrf_safety.py`.
- `marketplace.json` updated to seven skills with `audit-orchestrator` as entrypoint.

## BOUNDED CRAWLER & PRIORITY PIPELINE
- Enhanced `site-discovery-audit` and `audit-orchestrator`:
  - Layered URL predicate chain: Scheme, host boundary, non-HTML file extension filtering, crawl-trap suppression (search endpoints, pagination loops, parameter explosion), and depth ceiling (`max_depth = 3`).
  - Semantic priority queue: Scores and prioritizes representative page types (About, Products, Services, Contact, Pricing, FAQ, Articles) and prominent navigation links.
  - Sitemap discovery & index traversal: Evaluates `robots.txt` for declared sitemaps and recursively traverses sitemap indexes and urlsets, with safe fallback to `/sitemap.xml`.
  - Final URL propagation: Tracks redirect chains and propagates final resolved URLs to all downstream schema, canonical, and entity corroboration checks.
  - Host circuit breaker & soft-block detection: Automatically halts crawling a host after consecutive 5xx/timeout failures and detects HTTP 200 challenge/CAPTCHA responses.
  - Comprehensive coverage and readiness band reporting.
- Added test coverage in `tests/test_crawler_pipeline.py` and `tests/test_adversarial_fixture_e2e.py`.
- Full local test suite: 221 tests passed, 0 failed, 0 errors. Marketplace validator: passed.

