## 2024-05-23 - [DoS Protection via Input/Network Limits]
**Vulnerability:** The serverless handler was susceptible to Denial of Service (DoS) and Out-of-Memory (OOM) crashes because it accepted unlimited lists of newsletter URLs, unlimited posts per newsletter, and downloaded entire response bodies into memory without size checks.
**Learning:** `requests.get()` without `stream=True` downloads the full content immediately. In a memory-constrained environment (like serverless pods), this is a trivial vector for crashing the service by pointing it to a large file (e.g., 10GB ISO).
**Prevention:**
1. Enforce hard limits on all list inputs (e.g., `MAX_NEWSLETTERS`).
2. Always use `requests.get(stream=True)` for user-provided URLs.
3. Read the response stream in chunks and count bytes, aborting if the size exceeds a safety threshold (e.g., 2MB).

## 2026-01-25 - [SSRF Protection via Safe Request Handling]
**Vulnerability:** The application was vulnerable to Server-Side Request Forgery (SSRF) because `feedparser` and `requests.get` (without custom redirect handling) follow redirects automatically. An attacker could provide a safe-looking initial URL (e.g., `https://example.com`) that redirects to an internal service (e.g., `http://127.0.0.1:8080/secret`), bypassing the initial `is_safe_url` check.
**Learning:** Checking a URL once before the request is insufficient because redirects can lead to unsafe targets. Python's `requests` library follows redirects by default, exposing the application to this risk.
**Prevention:**
1. Implement a wrapper function (e.g., `safe_requests_get`) that disables automatic redirects (`allow_redirects=False`).
2. Manually follow redirects in a loop, validating the `Location` header against the allowlist/blocklist (`is_safe_url`) at every step.
3. Use `requests.Session()` to persist cookies across these manual redirect steps if needed.
