## 2024-05-23 - [DoS Protection via Input/Network Limits]
**Vulnerability:** The serverless handler was susceptible to Denial of Service (DoS) and Out-of-Memory (OOM) crashes because it accepted unlimited lists of newsletter URLs, unlimited posts per newsletter, and downloaded entire response bodies into memory without size checks.
**Learning:** `requests.get()` without `stream=True` downloads the full content immediately. In a memory-constrained environment (like serverless pods), this is a trivial vector for crashing the service by pointing it to a large file (e.g., 10GB ISO).
**Prevention:**
1. Enforce hard limits on all list inputs (e.g., `MAX_NEWSLETTERS`).
2. Always use `requests.get(stream=True)` for user-provided URLs.
3. Read the response stream in chunks and count bytes, aborting if the size exceeds a safety threshold (e.g., 2MB).

## 2026-01-21 - [SSRF Protection via Redirect Validation]
**Vulnerability:** The application was vulnerable to Server-Side Request Forgery (SSRF) because `requests.get` follows redirects by default, potentially allowing access to internal services (e.g., cloud metadata) even if the initial URL was validated. `feedparser` also fetched URLs insecurely.
**Learning:** Checking only the initial URL is insufficient. Attacks can bypass validation using HTTP redirects (301/302) to unsafe IPs. `requests` does not provide built-in safe redirect handling that validates each hop against an allowlist/blocklist.
**Prevention:**
1. Use a wrapper like `safe_requests_get` that disables auto-redirects (`allow_redirects=False`).
2. Manually handle redirects, validating the `Location` header against `is_safe_url` at every hop.
3. For libraries like `feedparser`, fetch content safely first, then parse the content string.
