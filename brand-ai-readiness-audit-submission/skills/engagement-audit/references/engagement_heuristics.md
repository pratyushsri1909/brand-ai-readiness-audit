# Engagement Heuristics

- Count literal DOM `<h1>` elements; ignore classes, IDs, text labels, H2/H3, and visual styling.
- Zero H1 is a medium structural issue; multiple H1s are a medium clarity issue.
- Very long uninterrupted paragraphs reduce scannability and context retention.
- Internal links provide context continuity; a body with no internal links is a potential dead end.
- Next actions should be detectable without guessing; use word-boundary anchored CTA vocabulary across both attributes and inner element text to avoid substring false positives.
- Validate `<link rel="canonical">` declarations: ensure exactly one canonical URL per document, strip fragments, resolve relative paths, and flag cross-origin divergences.
- Classify page intent using multiple corroborating signals (URL pattern, Schema.org @type, headings, and commerce markers) rather than a single isolated keyword.
