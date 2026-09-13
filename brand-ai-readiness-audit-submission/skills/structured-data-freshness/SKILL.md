---
name: structured-data-freshness
description: Audits JSON-LD robustness, machine-readable commerce facts, deterministic freshness reasoning, non-text facts, and cross-page entity consistency.
license: MIT
---

# Structured Data & Freshness Audit

## When to use
Use when evaluating whether important facts can be parsed accurately, trusted as current, extracted from semantic text rather than non-text media, and verified consistently across pages.

## Inputs
Shared target URL, raw HTML, HTTP headers, optional multi-page artifacts, and freshness threshold configuration.

## Procedure
1. Parse every JSON-LD block with scalar/type guards and isolated error handling.
2. Flatten arrays and `@graph` objects without allowing malformed blocks to suppress valid blocks.
3. Detect commerce context from overlapping price, CTA, and product signals rather than currency alone.
4. Perform deterministic stale-fact checks on datePublished/dateModified timestamps, OpenGraph metadata, and HTTP Last-Modified against configured age thresholds.
5. Identify facts locked in non-text media (infographics, charts, images without alt, canvas, SVG without title/desc) without hallucinating image content.
6. Check canonical/entity URL consistency, duplicate Organization definitions, and available `@id`/`sameAs` disambiguation.
7. Perform on-site cross-page corroboration to detect conflicting Organization identities and divergent product prices across sampled pages.

## Output
Evidence-backed findings about machine-readable facts, stale freshness signals, non-text fact locks, commerce semantics, and cross-page fact conflicts.
