# Cross-Page Entity Corroboration Reference Guide

## Principles
AI answer engines synthesize facts across multiple pages on a brand's domain. When different pages declare conflicting names for the same company or contradictory prices for the same product, AI summarizers hallucinate or report brand unreliability.

## Classification States
- **CONSISTENT**: All sampled pages agree on Organization identity attributes (name, @id, URL).
- **CONFLICTING**: The same declared identity identifier (@id or URL) states contradictory names or conflicting product prices across pages.
  - *Example*: `@id="https://example.com/#org"` named "Acme Corp" on the homepage and "Acme Global Solutions LLC" on the About page.
- **AMBIGUOUS**: Multiple distinct organizations declared without an overarching tying identifier. Treated as informative; never flagged as a defect because legitimate multi-brand enterprises often host distinct subsidiaries.
- **MISSING**: Key representative pages (Homepage, About) fail to declare any Organization entity.

## False-Positive Prevention
- Never flag an entity conflict simply because a company has multiple brand entities.
- Never resolve external `sameAs` links via third-party network requests.
