---
name: site-discovery-audit
description: Discovers site structure via robots.txt, XML sitemaps, and internal links, and deterministically plans representative page sampling within budget constraints.
license: MIT
---

# Site Discovery Audit

## When to use
Use during the initial phase of a domain audit to discover XML sitemaps, extract navigational link topologies, and deterministically assemble a bounded representative page plan (Homepage, About, Product/Service, Contact, Article) without unbounded crawling.

## Inputs
Target domain root URL, homepage raw HTML, robots.txt text payload, optional XML sitemap payloads, and a page budget limit (default: 20 pages; hard maximum 50 pages).

## Procedure
1. Inspect `robots.txt` payload for declared `Sitemap:` directives.
2. If XML sitemap is available, parse `<urlset>` or `<sitemapindex>` entries using standard XML tree parsing, bounded to at most 10 sitemap documents, with a maximum sitemap nesting depth of 3.
3. If sitemaps are missing or unparseable, fall back gracefully to extracting `<a href>` targets from the initial homepage HTML response.
4. Normalize all candidate URLs: lowercase scheme and host, resolve relative URLs against root via `urljoin`, strip port defaults, strip fragments, and remove tracking query parameters (`utm_*`, `gclid`, `fbclid`).
5. Filter candidate links strictly to the audited host origin.
6. Heuristically classify URLs into representative roles (Homepage, About, Product/Service, Contact, Category, Article) using deterministic pattern matching. Never invent or guess an ambiguous role.
7. Select up to the page budget limit and report the stopping condition (`budget_reached`, `runtime_budget_exhausted`, or `source_exhaustion`). Sitemap discovery is additionally bounded to 100 discovered sitemap URLs and 2 MB per sitemap response.

## Output
Emits findings on missing sitemap declarations alongside a typed page plan (`url`, `inferred_role`, `reason_selected`) and stopping condition metrics for consumption by multi-page entity corroboration and evidence coverage reporting.
