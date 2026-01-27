## 2024-05-23 - [DoS Protection via Input/Network Limits]
**Vulnerability:** The serverless handler was susceptible to Denial of Service (DoS) and Out-of-Memory (OOM) crashes because it accepted unlimited lists of newsletter URLs, unlimited posts per newsletter, and downloaded entire response bodies into memory without size checks.
**Learning:** `requests.get()` without `stream=True` downloads the full content immediately. In a memory-constrained environment (like serverless pods), this is a trivial vector for crashing the service by pointing it to a large file (e.g., 10GB ISO).
**Prevention:**
1. Enforce hard limits on all list inputs (e.g., `MAX_NEWSLETTERS`).
2. Always use `requests.get(stream=True)` for user-provided URLs.
3. Read the response stream in chunks and count bytes, aborting if the size exceeds a safety threshold (e.g., 2MB).

## 2025-01-27 - [SSRF via Redirects & Unverified Feed Parsing]
**Vulnerability:** The application used `feedparser.parse(url)` directly and `requests.get(url)` for scraping. Both libraries follow HTTP redirects by default, allowing attackers to bypass initial `is_safe_url` checks by providing a safe URL that redirects to an internal/private IP (TOCTOU/DNS Rebinding). Additionally, `handler.py` had a critical `NameError` due to missing imports.
**Learning:** Initial validation of a URL is insufficient if the HTTP client automatically follows redirects. `feedparser`'s internal HTTP client is difficult to secure against SSRF.
**Prevention:**
1. Implement a custom `safe_requests_get` that disables auto-redirects (`allow_redirects=False`) and validates the URL at every hop (checking `Location` header against `is_safe_url`).
2. For RSS feeds, fetch the content as bytes using the secure client first, then pass the data to `feedparser.parse()`.
