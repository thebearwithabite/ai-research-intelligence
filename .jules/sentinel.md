## 2024-05-23 - [DoS Protection via Input/Network Limits]
**Vulnerability:** The serverless handler was susceptible to Denial of Service (DoS) and Out-of-Memory (OOM) crashes because it accepted unlimited lists of newsletter URLs, unlimited posts per newsletter, and downloaded entire response bodies into memory without size checks.
**Learning:** `requests.get()` without `stream=True` downloads the full content immediately. In a memory-constrained environment (like serverless pods), this is a trivial vector for crashing the service by pointing it to a large file (e.g., 10GB ISO).
**Prevention:**
1. Enforce hard limits on all list inputs (e.g., `MAX_NEWSLETTERS`).
2. Always use `requests.get(stream=True)` for user-provided URLs.
3. Read the response stream in chunks and count bytes, aborting if the size exceeds a safety threshold (e.g., 2MB).

## 2026-01-15 - [SSRF Bypass via Redirects]
**Vulnerability:** The application validated URLs using `is_safe_url` but then passed them to `requests` and `feedparser` which follow redirects by default. An attacker could bypass the check by providing a safe URL that redirects to an unsafe internal IP (e.g., localhost).
**Learning:** Checking a URL once is insufficient if the HTTP client automatically follows redirects. Each hop in the redirect chain must be validated.
**Prevention:** Use a wrapper around the HTTP client (like `safe_requests_get`) that disables automatic redirects (`allow_redirects=False`), manually handles the redirect loop, and validates the `Location` header of every redirect against the security policy.
