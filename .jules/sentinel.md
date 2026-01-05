## 2024-05-23 - [DoS Protection via Input/Network Limits]
**Vulnerability:** The serverless handler was susceptible to Denial of Service (DoS) and Out-of-Memory (OOM) crashes because it accepted unlimited lists of newsletter URLs, unlimited posts per newsletter, and downloaded entire response bodies into memory without size checks.
**Learning:** `requests.get()` without `stream=True` downloads the full content immediately. In a memory-constrained environment (like serverless pods), this is a trivial vector for crashing the service by pointing it to a large file (e.g., 10GB ISO).
**Prevention:**
1. Enforce hard limits on all list inputs (e.g., `MAX_NEWSLETTERS`).
2. Always use `requests.get(stream=True)` for user-provided URLs.
3. Read the response stream in chunks and count bytes, aborting if the size exceeds a safety threshold (e.g., 2MB).

## 2026-01-05 - [SSRF Protection via Secure Redirect Handling]
**Vulnerability:** The application was vulnerable to Server-Side Request Forgery (SSRF) because `requests.get()` and `feedparser.parse()` automatically follow redirects. An attacker could provide a safe URL (e.g., `http://attacker.com`) that redirects to an internal resource (e.g., `http://169.254.169.254/latest/meta-data/` or `http://localhost`), bypassing the initial `is_safe_url` check.
**Learning:** Checking a URL once before fetching is insufficient if the HTTP client follows redirects. The Time-of-Check Time-of-Use (TOCTOU) gap allows the final destination to differ from the validated URL. `feedparser` also handles networking internally, making it hard to control.
**Prevention:**
1. Use a custom `safe_requests_get` wrapper that disables automatic redirects (`allow_redirects=False`).
2. Manually handle the redirect loop, validating every `Location` header against the allowlist/blocklist (`is_safe_url`) before following.
3. For libraries like `feedparser`, fetch the content as bytes using the secure wrapper first, then pass the raw data to the library.
