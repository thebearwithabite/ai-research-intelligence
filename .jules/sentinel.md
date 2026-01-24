## 2024-05-23 - [DoS Protection via Input/Network Limits]
**Vulnerability:** The serverless handler was susceptible to Denial of Service (DoS) and Out-of-Memory (OOM) crashes because it accepted unlimited lists of newsletter URLs, unlimited posts per newsletter, and downloaded entire response bodies into memory without size checks.
**Learning:** `requests.get()` without `stream=True` downloads the full content immediately. In a memory-constrained environment (like serverless pods), this is a trivial vector for crashing the service by pointing it to a large file (e.g., 10GB ISO).
**Prevention:**
1. Enforce hard limits on all list inputs (e.g., `MAX_NEWSLETTERS`).
2. Always use `requests.get(stream=True)` for user-provided URLs.
3. Read the response stream in chunks and count bytes, aborting if the size exceeds a safety threshold (e.g., 2MB).

## 2026-01-24 - [SSRF Bypass via Redirects]
**Vulnerability:** The application used `requests.get` and `feedparser.parse` which follow redirects by default. An attacker could bypass the `is_safe_url` check (which only validated the initial URL) by providing a safe URL that redirects to an unsafe internal IP (e.g., AWS metadata service).
**Learning:** Checking the initial URL is insufficient for SSRF protection when using libraries that automatically follow redirects.
**Prevention:**
1. Implement a custom `safe_requests_get` function that disables automatic redirects (`allow_redirects=False`).
2. Manually handle redirects in a loop, validating `is_safe_url` for the `Location` header of every 3xx response.
3. Use this safe function for all user-provided URLs, including RSS feeds (fetching content first, then parsing).
