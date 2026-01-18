## 2024-05-23 - [DoS Protection via Input/Network Limits]
**Vulnerability:** The serverless handler was susceptible to Denial of Service (DoS) and Out-of-Memory (OOM) crashes because it accepted unlimited lists of newsletter URLs, unlimited posts per newsletter, and downloaded entire response bodies into memory without size checks.
**Learning:** `requests.get()` without `stream=True` downloads the full content immediately. In a memory-constrained environment (like serverless pods), this is a trivial vector for crashing the service by pointing it to a large file (e.g., 10GB ISO).
**Prevention:**
1. Enforce hard limits on all list inputs (e.g., `MAX_NEWSLETTERS`).
2. Always use `requests.get(stream=True)` for user-provided URLs.
3. Read the response stream in chunks and count bytes, aborting if the size exceeds a safety threshold (e.g., 2MB).

## 2026-01-18 - [SSRF via Redirects in Feed Parsing]
**Vulnerability:** The application was vulnerable to Server-Side Request Forgery (SSRF) because `feedparser.parse()` and `requests.get()` were used on user-supplied URLs without checking for redirects to internal network addresses (e.g. localhost, 169.254.169.254). `is_safe_url` only validated the initial URL.
**Learning:** Standard HTTP libraries often follow redirects by default. Validating only the initial URL is insufficient as a malicious server can redirect a safe URL to an unsafe internal IP (Time-of-Check to Time-of-Use bypass).
**Prevention:**
1. Use a wrapper like `safe_requests_get` that disables automatic redirects (`allow_redirects=False`).
2. Manually handle redirects in a loop, validating the `Location` header against the allowlist/blocklist at every hop.
3. For libraries like `feedparser` that fetch URLs internally, fetch content explicitly using the safe wrapper first, then pass the raw content to the library.
