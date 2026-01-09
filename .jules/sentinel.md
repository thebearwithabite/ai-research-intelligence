## 2024-05-23 - [DoS Protection via Input/Network Limits]
**Vulnerability:** The serverless handler was susceptible to Denial of Service (DoS) and Out-of-Memory (OOM) crashes because it accepted unlimited lists of newsletter URLs, unlimited posts per newsletter, and downloaded entire response bodies into memory without size checks.
**Learning:** `requests.get()` without `stream=True` downloads the full content immediately. In a memory-constrained environment (like serverless pods), this is a trivial vector for crashing the service by pointing it to a large file (e.g., 10GB ISO).
**Prevention:**
1. Enforce hard limits on all list inputs (e.g., `MAX_NEWSLETTERS`).
2. Always use `requests.get(stream=True)` for user-provided URLs.
3. Read the response stream in chunks and count bytes, aborting if the size exceeds a safety threshold (e.g., 2MB).

## 2026-01-09 - SSRF Protection via Manual Redirect Handling
**Vulnerability:** Standard libraries like `requests` and `feedparser` automatically follow redirects to potentially unsafe IPs (e.g., 127.0.0.1) even if the initial URL is validated.
**Learning:** Checking a URL before request is insufficient due to redirects.
**Prevention:** Implemented `safe_requests_get` wrapper that manually follows redirects, validating `is_safe_url` at every hop, and preventing internal network access. Also ensures sensitive request parameters are not leaked across redirects.
