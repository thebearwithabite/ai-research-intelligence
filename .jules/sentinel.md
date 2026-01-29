## 2024-05-23 - [DoS Protection via Input/Network Limits]
**Vulnerability:** The serverless handler was susceptible to Denial of Service (DoS) and Out-of-Memory (OOM) crashes because it accepted unlimited lists of newsletter URLs, unlimited posts per newsletter, and downloaded entire response bodies into memory without size checks.
**Learning:** `requests.get()` without `stream=True` downloads the full content immediately. In a memory-constrained environment (like serverless pods), this is a trivial vector for crashing the service by pointing it to a large file (e.g., 10GB ISO).
**Prevention:**
1. Enforce hard limits on all list inputs (e.g., `MAX_NEWSLETTERS`).
2. Always use `requests.get(stream=True)` for user-provided URLs.
3. Read the response stream in chunks and count bytes, aborting if the size exceeds a safety threshold (e.g., 2MB).

## 2024-05-24 - [SSRF Protection via Manual Redirect Handling]
**Vulnerability:** `requests.get()` follows redirects by default, allowing attackers to bypass initial URL checks by redirecting to internal IPs (SSRF). Additionally, `feedparser.parse(url)` can use unsafe internal fetchers.
**Learning:** Initial validation of a URL (`is_safe_url`) is insufficient if the client follows redirects to unsafe destinations. SSRF protection requires checking *every* hop.
**Prevention:**
1. Use a wrapper like `safe_requests_get` that disables auto-redirects (`allow_redirects=False`).
2. Manually loop through redirects, validating the `Location` header against the allowlist/blocklist before following.
3. Strip sensitive headers (like `Authorization`) when redirecting across domains.
4. Fetch content securely using this wrapper before passing it to parsers like `feedparser`.
