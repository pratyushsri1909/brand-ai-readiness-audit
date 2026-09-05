---
name: audit-orchestrator
description: Sole entrypoint for a bounded, read-only website audit covering AI discoverability and on-site engagement.
license: MIT
---

# Audit Orchestrator

## When to use
Use this skill for the complete marketplace audit. It is the only skill intended to receive the external audit request.

## Inputs
A target HTTP or HTTPS URL supplied as a CLI argument.

## Procedure
1. Validate the URL scheme and host.
2. Fetch `robots.txt` once and apply a conservative robots policy before fetching the target page.
3. Fetch the target page once, bounded by timeout and response-size limits.
4. Pass the shared HTML and metadata to `crawl-render-audit`, `structured-data-freshness`, and `engagement-audit`.
5. Preserve partial detector results when one detector encounters an unexpected input.
6. Deduplicate equivalent findings and normalize severities to `critical`, `high`, or `medium`.
7. Emit a single deterministic report with severity counts matching the findings array.

## Output
A JSON object containing `site`, `audited_at`, `summary`, and `findings`. Every finding contains `id`, `title`, `severity`, `evidence`, and `suggested_action` with `summary` and `priority`.
