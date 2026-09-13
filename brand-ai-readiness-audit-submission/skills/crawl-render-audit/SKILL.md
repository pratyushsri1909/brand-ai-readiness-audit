---
name: crawl-render-audit
description: Audits crawler access, robots policy, meta robots, X-Robots-Tag directives, raw HTML readability, and client-rendering signals.
license: MIT
---

# Crawl & Render Audit

## When to use
Use on the shared page-fetch artifacts to determine whether a machine can safely reach, read, and index the page.

## Inputs
Shared audit artifact containing URL, HTTP status, headers, raw HTML, optional rendered HTML, and robots permission context.

## Procedure
1. Evaluate target HTTP status.
2. Confirm robots policy was respected by the orchestrator.
3. Inspect HTML meta robots/googlebot tags and HTTP X-Robots-Tag headers for noindex, nofollow, none, and conflicting directives.
4. Measure readable raw text and inspect conservative SPA/hydration indicators.
5. If rendered HTML is explicitly supplied or optionally rendered via Playwright, compare readable raw and rendered text lengths without fabricating DOMs.
6. Label static JS signals as inference; never fabricate a rendered DOM when browser execution is unavailable.

## Output
Finding objects covering crawler access, indexing directives, raw readability, and rendering-gap evidence with actionable remediation.
