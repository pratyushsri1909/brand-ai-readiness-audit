# Site Discovery Reference Guide

## Principles
AI agents and web crawlers need an efficient, bounded way to sample a domain's representative pages without drowning in deep pagination, parameter traps, or spidering millions of URLs.

## Discovery Hierarchy
1. **Robots.txt Sitemap Directives**:
   - Explicit declarations like `Sitemap: https://example.com/sitemap.xml` provide the most authoritative discovery source.
2. **Standard Sitemap Probe**:
   - If robots.txt omits directives, check root `/sitemap.xml`.
3. **Internal Navigation Fallback**:
   - If sitemaps are absent or unparseable, extract internal links from homepage navigation and body content.

## Role Classification Heuristics
- **Homepage**: Audited domain entrypoint.
- **Product/Service**: Detail pages featuring pricing, purchase CTAs, or SKU specifications (`/product/`, `/service/`).
- **Category/Catalog**: Collection listings showcasing multiple offerings (`/shop`, `/products`, `/collections`).
- **About**: Entity backstory and governance pages (`/about`, `/our-story`, `/company`).
- **Contact**: Customer service and communication channels (`/contact`, `/get-in-touch`).
- **Article/Blog**: Informational and news posts (`/blog/`, `/news/`, `/insights/`).

## Guardrails
- Discard external links and subdomain variations by default.
- Eliminate marketing tracking query parameters (`utm_*`, `gclid`, `fbclid`) to prevent duplicate URL sampling.
- Cap sampling at a strict budget (default 5 pages) to honor contest runtime constraints.
