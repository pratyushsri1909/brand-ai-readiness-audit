---
name: entity-corroboration-audit
description: Verifies cross-page identity, Organization entity schema consistency, and product price corroboration across sampled website pages without external lookups.
license: MIT
---

# Entity Corroboration Audit

## When to use
Use during multi-page site audits to ensure that brand identity (Organization name, @id, URL) and commercial facts (product pricing) remain consistent across all sampled pages.

## Inputs
A collection of sampled page artifacts from the site discovery plan, each providing URL, raw HTML, and headers.

## Procedure
1. Extract all JSON-LD entities from each sampled page's HTML response.
2. Group Organization schema declarations by their definitive identifier (`@id` URI or normalized `url`).
3. Compare declared names across instances. Flag CONFLICTING findings only when the same identity identifier declares contradictory names on different pages.
4. Treat distinct organizations without shared identity keys as AMBIGUOUS (multi-brand structures) without raising defect findings.
5. Cross-reference Product schema instances by name; flag conflicting advertised prices across sampled pages.
6. Restrict all corroboration strictly to deterministic on-site signals; perform zero external network lookups.

## Output
Emits high-severity findings for conflicting Organization identities or contradictory product pricing across pages, complete with page URLs and exact contradictory values.
