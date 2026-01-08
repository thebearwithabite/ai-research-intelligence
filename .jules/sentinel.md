
## 2024-05-20 - SSRF in Feed Parsing
**Vulnerability:** Server-Side Request Forgery (SSRF) in RSS feed fetching.
**Learning:** `feedparser.parse(url)` directly fetches the URL, which might bypass custom SSRF checks if the library handles redirects internally or if the URL validation is done separately from the fetch.
**Prevention:** Fetch content using a secure request wrapper (like `safe_requests_get`) first, then pass the content (bytes) to `feedparser.parse()`.
