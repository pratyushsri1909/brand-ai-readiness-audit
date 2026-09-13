# Crawl & Render Checklist

- Validate HTTP reachability and surface 4xx/5xx failures with evidence.
- Respect robots.txt before the target page is fetched; 404 means no published robots file, while permission-uncertain failures halt the crawl.
- Inspect HTML meta robots/googlebot tags and HTTP X-Robots-Tag headers for noindex, nofollow, and conflicting directives.
- Highlight cases where robots.txt allows crawling but page markup specifies noindex.
- Measure readable text in the raw payload rather than counting scripts as content.
- Treat empty SPA mounts, hydration markers, and script-heavy/low-text payloads as static JS-risk inference only.
- Compare raw and rendered text when a rendered artifact is explicitly available or rendered via optional Playwright integration; never fabricate DOM content.
