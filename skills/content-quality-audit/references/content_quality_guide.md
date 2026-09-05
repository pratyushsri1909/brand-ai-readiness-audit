# Content Quality Reference Guide

## Thin Content Thresholds (page-type-sensitive)

| Page Type | Minimum Words |
|-----------|---------------|
| article/blog | 250 |
| product/service | 80 |
| homepage | 50 |
| category/catalog | 50 |
| about/company | 100 |
| contact/support | 40 |
| faq | 100 |
| general/unknown | 100 |

These thresholds are deliberately conservative to avoid false-positive defect claims.

## Similarity Thresholds

| Check | Method | Threshold |
|-------|--------|-----------|
| Exact duplicate | SHA-256 of normalised body | hash match |
| Near-duplicate | Character 3-gram Jaccard | >= 0.85 |
| Potential topic overlap | Term Jaccard (top 10 terms) | >= 0.70 |

## Meta Description Guidelines

- Recommended length: 50-160 characters
- Maximum before likely truncation: 320 characters
- Must be present on every indexable page

## Important Labelling Rules

- Do NOT call topic overlap "keyword cannibalization" without search performance data.
- Thin content is flagged per page type, not with a universal 300-word rule.
- Near-duplicate findings require review: shared nav/footer text may inflate similarity.
- Exact duplicate findings are high severity because they represent clear source-attribution ambiguity.
