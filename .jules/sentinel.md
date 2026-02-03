## 2024-05-23 - [DoS Protection via Input/Network Limits]
**Vulnerability:** The serverless handler was susceptible to Denial of Service (DoS) and Out-of-Memory (OOM) crashes because it accepted unlimited lists of newsletter URLs, unlimited posts per newsletter, and downloaded entire response bodies into memory without size checks.
**Learning:** `requests.get()` without `stream=True` downloads the full content immediately. In a memory-constrained environment (like serverless pods), this is a trivial vector for crashing the service by pointing it to a large file (e.g., 10GB ISO).
**Prevention:**
1. Enforce hard limits on all list inputs (e.g., `MAX_NEWSLETTERS`).
2. Always use `requests.get(stream=True)` for user-provided URLs.
3. Read the response stream in chunks and count bytes, aborting if the size exceeds a safety threshold (e.g., 2MB).

## 2026-02-03 - [SSRF Bypass via Redirects]
**Vulnerability:** `is_safe_url` validation was only applied to the initial URL. Attackers could bypass SSRF protection by providing a safe URL that redirects to an internal IP (e.g., `http://127.0.0.1`), as `requests` and `feedparser` follow redirects by default.
**Learning:** Checking the initial URL is insufficient. Libraries often follow redirects automatically, invalidating the initial check.
**Prevention:**
1. Use a custom fetch function (`safe_requests_get`) that disables auto-redirects (`allow_redirects=False`).
2. Manually handle redirects and validate `is_safe_url` for *every* hop.
3. For libraries like `feedparser` that don't support granular control, fetch content safely first as bytes/string, then pass it to the parser.
