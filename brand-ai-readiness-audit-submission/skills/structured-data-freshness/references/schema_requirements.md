# Structured Data & Freshness Requirements

- Parse all JSON-LD blocks independently; malformed JSON must not suppress later valid blocks.
- Skip valid scalar JSON roots safely; only dictionaries represent entity objects.
- Arrays and `@graph` must be flattened safely.
- A currency symbol alone is not a commerce finding. Require overlapping price, purchase CTA, and product/inventory context before recommending Product/Offer schema.
- Content freshness requires deterministic date reasoning: evaluate datePublished, dateModified, OpenGraph article dates, and HTTP Last-Modified against a reference audit date and conservative age threshold (e.g. 730 days).
- Never claim old facts are "definitely false"; phrase as "potentially stale" or "outdated freshness signal".
- Detect facts locked in non-text media (infographics, diagrams, pricing charts, images without alt, canvas, uncaptioned SVGs) without fabricating or guessing visual content.
- Entity ambiguity and cross-page conflict checks must rely on deterministic on-site evidence quoting both URLs and conflicting values. Clearly label as on-site corroboration.
- Never claim external corroboration without actually executing external network resolution.
