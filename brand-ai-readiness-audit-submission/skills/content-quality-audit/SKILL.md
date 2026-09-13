---
name: content-quality-audit
description: Detects thin content, exact/near-duplicate pages, potential topic overlap, and metadata gaps across sampled website pages using deterministic, defensible signals without external lookups.
license: MIT
---

# Content Quality Audit

## When to use
Use during multi-page site audits to evaluate whether sampled pages carry sufficient, unique, well-structured content for AI machine readers. Complements the engagement-audit (which focuses on H1/CTA/navigation) and the structured-data-freshness skill (which focuses on schema validity).

## Inputs
A collection of sampled page artifacts, each providing URL, raw HTML, and inferred page role.

## Procedure

### A. Thin Content Detection
1. Extract visible text by stripping HTML tags, script, and style blocks.
2. Compute word count on the cleaned text.
3. Apply page-type-sensitive thresholds (article: 250 words, product: 80 words, homepage/category: 50 words, general: 100 words).
4. Do NOT universally classify under-300-word pages as defective. Context matters.

### B. Exact Duplicate Detection
1. Normalize body text: lowercase, collapse whitespace, strip punctuation.
2. Compute SHA-256 digest of the normalized content.
3. Flag pairs of pages with identical digests.

### C. Near-Duplicate Detection
1. Use shingling (character 3-grams) on normalized text, capped at 200 shingles.
2. Estimate Jaccard similarity: |intersection| / |union|.
3. Flag pairs with Jaccard >= 0.85 as near-duplicates.

### D. Potential Topic Overlap
1. Extract top-10 normalized content terms (lowercase, alphabetic, length >= 5).
2. Compute term-based Jaccard similarity between page pairs.
3. Flag pairs with term Jaccard >= 0.70 as potential topic overlap.
4. Label findings as "Potential Topic Overlap" - NOT "keyword cannibalization".

### E. Metadata Completeness
1. Check for presence and quality of meta description on each page.
2. Flag missing or empty meta descriptions.
3. Flag meta descriptions > 320 characters (likely truncated by search engines).

## Output
Emits findings for thin content, exact duplicates, near-duplicates, potential topic overlap, and missing meta descriptions. Evidence identifies affected URLs and measured similarity scores.

## Constraints
- Zero external network requests.
- Deterministic: same inputs always produce identical outputs.
- Never labels overlap as "keyword cannibalization" without search query data.
- Applies page-type-aware thresholds for thin content.
