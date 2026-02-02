## 2024-05-23 - [DoS Protection via Input/Network Limits]
**Vulnerability:** The serverless handler was susceptible to Denial of Service (DoS) and Out-of-Memory (OOM) crashes because it accepted unlimited lists of newsletter URLs, unlimited posts per newsletter, and downloaded entire response bodies into memory without size checks.
**Learning:** `requests.get()` without `stream=True` downloads the full content immediately. In a memory-constrained environment (like serverless pods), this is a trivial vector for crashing the service by pointing it to a large file (e.g., 10GB ISO).
**Prevention:**
1. Enforce hard limits on all list inputs (e.g., `MAX_NEWSLETTERS`).
2. Always use `requests.get(stream=True)` for user-provided URLs.
3. Read the response stream in chunks and count bytes, aborting if the size exceeds a safety threshold (e.g., 2MB).

## 2026-02-02 - [SSRF via Redirects and Library Fetching]
**Vulnerability:** The application was vulnerable to Server-Side Request Forgery (SSRF) because `feedparser.parse(url)` fetches content internally without validating redirects, and `requests.get()` follows redirects by default. A user could provide a safe URL (e.g., `http://safe.com`) that redirects to a private IP (e.g., `http://169.254.169.254`), bypassing the initial `is_safe_url` check.
**Learning:** Checking a URL once before the request is insufficient ("Time-of-Check to Time-of-Use" or TOCTOU). Redirects often bypass initial validation. Also, libraries like `feedparser` may have insecure default fetching behaviors.
**Prevention:**
1. Use a custom `safe_requests_get` wrapper that disables auto-redirects (`allow_redirects=False`).
2. Manually handle redirects, validating the `Location` header against `is_safe_url` at every hop.
3. Fetch content as bytes using the safe wrapper first, then pass the *content* (not the URL) to parsers like `feedparser`.
