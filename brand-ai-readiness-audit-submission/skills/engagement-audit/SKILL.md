---
name: engagement-audit
description: Audits page orientation, heading hierarchy, scannability, navigation, canonical link robustness, page intent, and obvious next actions.
license: MIT
---

# Engagement Audit

## When to use
Use on the shared raw HTML to identify structural friction, canonical ambiguities, uninformative titles, and navigation barriers after a visitor reaches the page.

## Inputs
Target URL, raw HTML, and page host context.

## Procedure
1. Parse actual HTML heading elements, not CSS classes or text that merely says h1.
2. Check page title descriptiveness and H1 orientation; flag generic placeholder titles.
3. Validate canonical link tags for duplicates, conflicts, URL fragments, and cross-origin declarations.
4. Classify page intent using multi-signal heuristics (path, schema types, headings, and commerce markers).
5. Flag multiple H1s and very dense paragraphs (> 800 characters without a break).
6. Check for internal navigation and clear, word-bounded next-action/CTA signals in both attributes and inner text.

## Output
Evidence-backed findings describing orientation, canonical integrity, scannability, navigation, and engagement barriers.
